/**
 * NemoIR Web Runtime — runtime agent factory.
 *
 * Provides a generic `WorkflowAgent` that decodes the raw manifest, merges
 * supplied tools with built-in `user.elicit`/`user.confirm` UI-host adapters,
 * and exposes `run()` / `stream()` backed by `WorkflowRuntime` +
 * `ModelStageExecutor`.
 *
 * The generated `agent.ts` (emitted by `nemoir-backend-web`) wraps this
 * factory as a typed per-workflow facade.
 */

import type { WorkflowIrJson } from "./ir.js";
import { decodeWorkflowIr } from "./ir.js";
import { buildWorkflowManifest, type WorkflowManifest } from "./manifest.js";
import { ModelStageExecutor, type ActionProtocol } from "./models.js";
import {
  DeterministicStageExecutor,
  selectDeterministicTool,
} from "./deterministic.js";
import {
  createBrowserTools,
  type BrowserToolsOptions,
} from "./browser-tools.js";
import { WorkflowRuntime, type StageContext, type StageExecutor } from "./runtime.js";
import type { RunOptions, WorkflowResult } from "./runtime-types.js";
import type { WorkflowEvent } from "./events.js";
import {
  type ModelAdapter,
  type ModelRouter,
} from "./model-contract.js";
import {
  ToolRegistry,
  type Tool,
} from "./tools.js";
import type { WebUiHost } from "./ui-host.js";

// ---------------------------------------------------------------------------
// Agent options
// ---------------------------------------------------------------------------

export interface WorkflowAgentOptions {
  /** A concrete ModelAdapter (for tests, or power users). */
  modelAdapter?: ModelAdapter | ModelRouter;
  /**
   * Tool registry. Caller-supplied tools are merged with built-in UI-host
   * adapters. If the workflow requires `user.elicit`/`user.confirm`, a
   * `uiHost` must be provided unless the caller supplies their own tools
   * for those capabilities.
   */
  tools?: ToolRegistry | Iterable<Tool>;
  /** UI host for browser-safe capabilities. Required if the workflow uses user.elicit/user.confirm. */
  uiHost?: WebUiHost;
  /**
   * Options for browser-native tools (http.fetch, browser.storage.*, browser.js.run).
   * Pass `jsWorkerFactory` when the workflow uses `browser.js.run`.
   */
  browserTools?: BrowserToolsOptions;
  /** Default run options (can be overridden per run). */
  defaults?: Partial<RunOptions>;
  /**
   * Model action protocol. Defaults to "native" (adapter returns
   * `ModelResponse.toolCalls`). WebLLM and other small/local models should
   * use "tagged_envelope" (model returns tagged JSON in content text). The
   * generated web facade defaults to "tagged_envelope".
   */
  actionProtocol?: ActionProtocol;
}

// ---------------------------------------------------------------------------
// Built-in UI-host tools
// ---------------------------------------------------------------------------

function createUiTools(uiHost: WebUiHost): Tool[] {
  const tools: Tool[] = [];

  // user.elicit
  tools.push({
    name: "elicit",
    capability: "user.elicit",
    description: "Ask the user a question and get a string response. Pass `options` to restrict the answer to a fixed set of choices.",
    inputSchema: { question: "string", options: "string[]" },
    handler: async (args, ctx) => {
      const question = args.question as string;
      const options = Array.isArray(args.options) ? (args.options as string[]) : undefined;
      const signal = ctx.signal ?? undefined;
      return uiHost.elicit(question, options, signal);
    },
  });

  // user.confirm
  tools.push({
    name: "confirm",
    capability: "user.confirm",
    description: "Ask the user for confirmation (yes/no)",
    inputSchema: { message: "string" },
    handler: async (args, ctx) => {
      const message = args.message as string;
      const signal = ctx.signal ?? undefined;
      return uiHost.confirm(message, signal);
    },
  });

  return tools;
}

/**
 * Merge caller-supplied tools with built-in UI-host tools.
 *
 * Caller tools take precedence: if the caller provides a tool for
 * `user.elicit` or `user.confirm`, the built-in UI-host adapter is not
 * registered for that capability.
 */
function mergeTools(
  callerTools: ToolRegistry | Iterable<Tool> | undefined,
  uiTools: Tool[],
): ToolRegistry {
  const all: Tool[] = [];
  const capabilitiesCovered = new Set<string>();

  // Add caller tools first
  if (callerTools) {
    const toolsIter = Symbol.iterator in callerTools
      ? (callerTools as Iterable<Tool>)
      : [];
    for (const t of toolsIter) {
      all.push(t);
      capabilitiesCovered.add(t.capability);
    }
  }

  // Add UI tools not already covered
  for (const t of uiTools) {
    if (!capabilitiesCovered.has(t.capability)) {
      all.push(t);
    }
  }

  return new ToolRegistry(all);
}

// ---------------------------------------------------------------------------
// WorkflowAgent
// ---------------------------------------------------------------------------

export class WorkflowAgent {
  private readonly manifest: WorkflowManifest;
  private readonly tools: ToolRegistry;
  private readonly modelAdapter?: ModelAdapter | ModelRouter;
  private readonly defaults?: Partial<RunOptions>;
  private readonly actionProtocol?: ActionProtocol;

  constructor(rawIr: unknown, opts: WorkflowAgentOptions) {
    // Decode + web-validate the raw IR
    const ir: WorkflowIrJson = decodeWorkflowIr(rawIr);
    this.manifest = buildWorkflowManifest(ir);
    this.actionProtocol = opts.actionProtocol;

    // Check that a model adapter is provided when the workflow has model stages.
    // Deterministic-only workflows do not need a model adapter.
    const hasModelStages = this.manifest.stages.some(
      (s) => s.execution.kind === "model",
    );
    if (hasModelStages && !opts.modelAdapter) {
      throw new Error(
        "WorkflowAgent requires a modelAdapter for workflows with model stages. " +
          "Pass a WebLLM adapter via `createWebllmAdapter` or inject a fake adapter for tests.",
      );
    }
    // Store undefined for deterministic-only workflows.
    this.modelAdapter = opts.modelAdapter!;

    // Build UI tools if a UI host is provided
    const uiTools = opts.uiHost ? createUiTools(opts.uiHost) : [];

    // Build browser-native tools
    const browserNativeTools = createBrowserTools(opts.browserTools ?? {});

    // Merge tools: caller first, then UI, then browser-native.
    this.tools = mergeTools(opts.tools, [...uiTools, ...browserNativeTools]);

    // Check that all workflow capabilities are satisfied
    this.tools.requireCapabilities(this.manifest.capabilities);

    // Check that UI-host-dependent capabilities have a UI host
    for (const cap of this.manifest.capabilities) {
      if (cap === "user.elicit" || cap === "user.confirm") {
        const tool = this.tools.get(cap);
        if (tool && (tool.name === "elicit" || tool.name === "confirm") && !opts.uiHost) {
          throw new Error(
            `Workflow requires '${cap}' but no uiHost was provided. Either pass uiHost or provide your own tool for '${cap}'.`,
          );
        }
      }
    }

    this.defaults = opts.defaults;
  }

  get workflowId(): string {
    return this.manifest.workflowId;
  }

  get requiredCapabilities(): ReadonlySet<string> {
    return this.manifest.capabilities;
  }

  /**
   * Run the workflow, returning the result.
   */
  async run(
    inputs: Record<string, unknown>,
    opts?: {
      options?: Partial<RunOptions>;
      eventSink?: import("./events.js").WorkflowEventSink | null;
    },
  ): Promise<WorkflowResult> {
    const runtime = this.createRuntime(opts?.options);
    return runtime.run(inputs, {
      options: opts?.options,
      eventSink: opts?.eventSink,
    });
  }

  /**
   * Stream workflow events as they happen.
   */
  async *stream(
    inputs: Record<string, unknown>,
    opts?: { options?: Partial<RunOptions> },
  ): AsyncIterable<WorkflowEvent> {
    const runtime = this.createRuntime(opts?.options);
    yield* runtime.stream(inputs, { options: opts?.options });
  }

  private createRuntime(options?: Partial<RunOptions>): WorkflowRuntime {
    const resolvedOptions = options ?? this.defaults;
    const maxToolRounds = resolvedOptions?.maxToolRounds ?? 32;

    // Build deterministic executor + tool selection plan for tool stages
    const toolForStage = new Map<string, string>();
    for (const stage of this.manifest.stages) {
      if (stage.execution.kind === "tool") {
        const toolName = selectDeterministicTool(stage, this.tools);
        if (!toolName) {
          throw new Error(
            `No tool registered for deterministic stage '${stage.id}' (capability '${stage.execution.capability ?? ""}')`,
          );
        }
        toolForStage.set(stage.id, toolName);
      }
    }
    const deterministicExecutor = new DeterministicStageExecutor({
      tools: this.tools,
      toolForStage,
    });

    // Build model executor (may be unused if no model stages exist)
    const modelExecutor = this.modelAdapter
      ? new ModelStageExecutor({
          model: this.modelAdapter,
          tools: this.tools,
          maxToolRounds,
          actionProtocol: this.actionProtocol ?? "native",
        })
      : null;

    // Composite executor that dispatches by stage execution kind
    const executor: StageExecutor = {
      async execute(ctx: StageContext): Promise<Record<string, unknown>> {
        if (ctx.stage.execution.kind === "tool") {
          return deterministicExecutor.execute(ctx);
        }
        if (modelExecutor) {
          return modelExecutor.execute(ctx);
        }
        throw new Error(
          `Stage '${ctx.stage.id}' is a model stage but no modelAdapter is configured.`,
        );
      },
    };

    return new WorkflowRuntime({
      manifest: this.manifest,
      tools: this.tools,
      stageExecutor: executor,
    });
  }
}

// Re-export the StageExecutor interface for callers that want custom executors
export type { StageContext, StageExecutor };
