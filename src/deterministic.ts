/**
 * NemoIR Web Runtime — deterministic stage executor.
 *
 * Ports `DeterministicStageExecutor` from
 * `python/nemoir-runtime/src/nemoir_runtime/runtime.py`.
 *
 * Executes a `StageExecution::Tool` stage by calling one fixed capability
 * with resolved args. No model call. Routes through `ctx.callTool` so
 * policies, capability visibility, events, and output validation are all
 * enforced — exactly like a model-issued tool call.
 */

import { getCapability } from "./capabilities.js";
import { DataUnavailableError, StageOutputValidationError } from "./errors.js";
import type { ExprSpec, StageSpec } from "./manifest.js";
import type { StageContext, StageExecutor } from "./runtime.js";
import type { ToolRegistry } from "./tools.js";

/**
 * Resolve a single exec arg expression to a concrete value.
 *
 * Mirrors Python `DeterministicStageExecutor._resolve_exec_arg`. The DSL
 * lowers structured `json` literals natively (grammar `json_value`), so the
 * IR `Expr::Literal` already carries the parsed object/array — no string
 * coercion is needed. A `json`-typed param that receives a *string* value
 * is a hand-authored-manifest error and is rejected fail-closed.
 */
function resolveExecArg(
  expr: ExprSpec,
  inputs: Record<string, unknown>,
  readableContext: Record<string, unknown>,
  capability: string,
  argName: string,
): unknown {
  let value: unknown;
  if (expr.kind === "literal") {
    value = expr.value;
  } else if (expr.kind === "ref") {
    if (expr.ref === undefined || expr.ref === null) {
      throw new DataUnavailableError("exec arg expression has no ref");
    }
    if (expr.ref.kind === "input") {
      const name = expr.ref.name ?? "";
      value = inputs[name];
    } else if (expr.ref.kind === "node_output") {
      const node = expr.ref.node ?? "";
      const field = expr.ref.field ?? "";
      value = readableContext[`${node}.${field}`];
    } else {
      throw new DataUnavailableError(
        `unsupported exec arg ref kind '${expr.ref.kind}'`,
      );
    }
  } else {
    throw new DataUnavailableError(
      `unsupported exec arg expression kind '${expr.kind}'`,
    );
  }

  // Fail-closed defense: the DSL lowers `json` literals natively, so a
  // `json`-typed param must receive a structured value, not a string. A
  // string here means a hand-authored manifest is tunneling JSON through a
  // string literal — reject it with a clear error rather than silently
  // `JSON.parse`-ing (which would hide malformed payloads).
  if (typeof value === "string") {
    const spec = getCapability(capability);
    if (spec) {
      const param = spec.requiredParams.find((p) => p.name === argName);
      if (param?.type === "json") {
        throw new DataUnavailableError(
          `exec arg '${argName}' for capability '${capability}' has type 'json' ` +
            `but value is a string; use a JSON literal (e.g. { "key": ... }) ` +
            `instead of a string-encoded payload`,
        );
      }
    }
  }

  return value;
}

/**
 * Normalize a deterministic tool result to stage outputs.
 *
 * Mirrors Python `DeterministicStageExecutor._normalize_deterministic_output`:
 * - empty writes → {}
 * - Mapping/object → project to declared write names
 * - no `path` coercion (web target has no `path` type)
 * - supports scalar results: when a stage has exactly one declared write,
 *   a scalar result (string, bool, number, null) is wrapped as `{writeName: result}`
 */
function normalizeDeterministicOutput(
  stage: StageSpec,
  result: unknown,
): Record<string, unknown> {
  if (stage.writes.length === 0) {
    return {};
  }

  let raw: Record<string, unknown>;

  if (
    typeof result === "object" &&
    result !== null &&
    !Array.isArray(result)
  ) {
    raw = result as Record<string, unknown>;
  } else if (
    stage.writes.length === 1
  ) {
    // Scalar result for a single-write stage — wrap it.
    raw = { [stage.writes[0].name]: result };
  } else {
    throw new StageOutputValidationError(
      `deterministic stage '${stage.id}' requires an object result; ` +
        `got ${typeof result === "string" ? `string "${result}"` : String(result)}`,
    );
  }

  // Project: keep only declared write names
  const output: Record<string, unknown> = {};
  for (const w of stage.writes) {
    if (w.name in raw) {
      output[w.name] = raw[w.name];
    }
  }
  return output;
}

// ---------------------------------------------------------------------------
// DeterministicStageExecutor
// ---------------------------------------------------------------------------

export class DeterministicStageExecutor implements StageExecutor {
  /** stageId -> toolName selection plan (pre-computed at construction). */
  private readonly toolForStage: ReadonlyMap<string, string>;

  constructor(opts: {
    tools: ToolRegistry;
    toolForStage: ReadonlyMap<string, string>;
  }) {
    void opts.tools; // tools is consumed by the selection plan, not directly
    this.toolForStage = opts.toolForStage;
  }

  async execute(ctx: StageContext): Promise<Record<string, unknown>> {
    const execSpec = ctx.stage.execution;
    const capability = execSpec.capability ?? "";

    const toolName = this.toolForStage.get(ctx.stage.id);
    if (!toolName) {
      throw new DataUnavailableError(
        `no deterministic tool selected for stage '${ctx.stage.id}'`,
      );
    }

    // Resolve exec args
    const resolvedArgs: Record<string, unknown> = {};
    if (execSpec.args) {
      for (const [argName, expr] of execSpec.args) {
        resolvedArgs[argName] = resolveExecArg(
          expr,
          ctx.inputs,
          ctx.readableContext,
          capability,
          argName,
        );
      }
    }

    // Call through ctx.callTool (policy enforcement, events)
    const result = await ctx.callTool(capability, resolvedArgs, toolName);

    // Normalize to stage outputs
    return normalizeDeterministicOutput(ctx.stage, result);
  }
}

/**
 * Select the concrete tool for a deterministic stage.
 *
 * Mirrors Python `WorkflowRuntime._select_deterministic_tool`. Raises
 * `WorkflowValidationError` when no tool matches or multiple tools equally
 * satisfy (ambiguity) — matching Python's fail-fast behavior.
 */
export function selectDeterministicTool(
  stage: StageSpec,
  tools: ToolRegistry,
): string | null {
  const capability = stage.execution.capability ?? "";
  const stageTools = tools.toolsForCapabilities([capability]);

  if (stageTools.length === 0) return null;

  // When only one tool is registered for the capability, use it.
  if (stageTools.length === 1) {
    return stageTools[0].name;
  }

  // Multiple tools: filter by input params — all exec args must be
  // present in the tool's input schema.
  const execArgNames = new Set(execArgNamesFromStage(stage));
  const candidates = stageTools.filter((t) => {
    const toolParams = new Set(Object.keys(t.inputSchema));
    // Every tool param with no default must be present in exec args
    for (const tp of toolParams) {
      if (!execArgNames.has(tp)) return false;
    }
    return true;
  });

  if (candidates.length === 0) {
    return null;
  }
  if (candidates.length > 1) {
    // Match Python: ambiguity is an error.
    const names = candidates.map((t) => t.name).join(", ");
    throw new Error(
      `Deterministic stage '${stage.id}' (capability '${capability}'): ` +
        `multiple tools equally satisfy the stage: ${names}. ` +
        `Register fewer matching tools for '${capability}', or use ` +
        `additional stage outputs so only one tool matches.`,
    );
  }
  return candidates[0].name;
}

function execArgNamesFromStage(stage: StageSpec): string[] {
  if (!stage.execution.args) return [];
  return [...stage.execution.args.keys()];
}
