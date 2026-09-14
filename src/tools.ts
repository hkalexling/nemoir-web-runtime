/**
 * NemoIR Web Runtime — tool abstraction layer.
 *
 * Ports `python/nemoir-runtime/src/nemoir_runtime/tools.py`.
 *
 * Binds concrete async handlers to capability names, with catalog-driven
 * validation at registration time.
 */

import {
  type CapabilityParamType,
  getCapability,
} from "./capabilities.js";
import {
  MissingCapabilityError,
  NemoIRRuntimeError,
  ToolValidationError,
  ToolInvocationError,
} from "./errors.js";

export interface ToolContext {
  readonly workflowId: string;
  readonly stageId: string;
  readonly inputs: Record<string, unknown>;
  readonly metadata: Record<string, unknown>;
  /** Cancellation signal for the owning run. Long-running tool handlers
   * (e.g. UI-host prompts) should observe this. */
  readonly signal?: AbortSignal;
}

export type ToolHandler = (
  args: Record<string, unknown>,
  ctx: ToolContext,
) => Promise<unknown>;

/**
 * A tool parameter type.
 * Mirrors Python's supported parameter types: `string`, `bool`, `number`,
 * `Path` (mapped to `string` on web), `string[]`, `string[] | null`.
 */
export type ToolParamType =
  | "string"
  | "boolean"
  | "number"
  | "string[]"
  | "string[] | null"
  | "json";

export interface Tool {
  readonly name: string;
  readonly capability: string;
  readonly description: string;
  readonly inputSchema: Record<string, ToolParamType>;
  readonly handler: ToolHandler;
  readonly outputSchema?: Record<string, string> | null;
  /**
   * Optional runtime pre-policy preflight: called with the resolved tool args
   * before deny/before policies run. Lets a tool reject an input (e.g. an
   * oversized `code` value) before any confirmation UI renders or the handler
   * is invoked. Throws a NemoIRRuntimeError subclass to fail closed.
   */
  readonly preflight?: (args: Record<string, unknown>) => void;
}

/** Map a catalog param type to the NemoIR web type. */
function catalogTypeToParamType(ty: CapabilityParamType): ToolParamType {
  switch (ty) {
    case "string":
      return "string";
    case "bool":
      return "boolean";
    case "path":
      return "string";
    case "json":
      return "json";
  }
}

const SUPPORTED_PARAM_TYPES: ReadonlySet<ToolParamType> = new Set([
  "string",
  "boolean",
  "number",
  "json",
  "string[]",
  "string[] | null",
]);

/**
 * Validate that a tool meets its capability catalog contract.
 *
 * Mirrors Python `ToolRegistry._validate_tool_params`.
 */
function validateTool(tool: Tool): void {
  const spec = getCapability(tool.capability);
  if (!spec) {
    throw new ToolValidationError(
      `Tool '${tool.name}' declares unknown capability '${tool.capability}'`,
    );
  }

  // Handler must be async (return a Promise)
  if (typeof tool.handler !== "function") {
    throw new ToolValidationError(`Tool '${tool.name}' handler must be a function`);
  }

  // Every catalog-required param must be present with the correct type
  for (const param of spec.requiredParams) {
    // Optional catalog params may be omitted from the tool's input schema.
    if (param.required === false) continue;
    const expected = catalogTypeToParamType(param.type);
    const actual = tool.inputSchema[param.name];
    if (actual === undefined) {
      throw new ToolValidationError(
        `Tool '${tool.name}' declares capability '${tool.capability}' but is missing required parameter '${param.name}: ${expected}'`,
      );
    }
    if (actual !== expected) {
      throw new ToolValidationError(
        `Tool '${tool.name}' parameter '${param.name}' has type '${actual}', expected '${expected}' for capability '${tool.capability}'`,
      );
    }
  }

  // Tool-specific params must have supported types
  for (const [name, ty] of Object.entries(tool.inputSchema)) {
    const isCatalogRequired = spec.requiredParams.some((p) => p.name === name);
    if (!isCatalogRequired && !SUPPORTED_PARAM_TYPES.has(ty)) {
      throw new ToolValidationError(
        `Tool '${tool.name}' parameter '${name}' has unsupported type '${ty}'`,
      );
    }
  }
}

export class ToolRegistry implements Iterable<Tool> {
  private readonly byCapability = new Map<string, Tool[]>();
  private readonly byName = new Map<string, Tool>();

  [Symbol.iterator](): Iterator<Tool> {
    return this.byName.values();
  }

  constructor(tools: Iterable<Tool>) {
    const toolList = [...tools];
    for (const t of toolList) {
      if (this.byName.has(t.name)) {
        throw new ToolValidationError(`duplicate tool name: ${t.name}`);
      }
      this.byName.set(t.name, t);
      let list = this.byCapability.get(t.capability);
      if (!list) {
        list = [];
        this.byCapability.set(t.capability, list);
      }
      list.push(t);
    }
    // Validate after registration through the overridable hook, mirroring the
    // Python `self._validate_tools(...)` dispatch (synthetic registries such as
    // taped replay skip catalog checks for their stub tools).
    this._validateTools(toolList);
  }

  /** Validate tools against the capability catalog (overridable). */
  protected _validateTools(tools: readonly Tool[]): void {
    for (const t of tools) validateTool(t);
  }

  /** Returns the first tool for a capability, or undefined. */
  get(capability: string): Tool | undefined {
    return this.byCapability.get(capability)?.[0];
  }

  getByName(name: string): Tool | undefined {
    return this.byName.get(name);
  }

  toolsForCapabilities(caps: Iterable<string>): Tool[] {
    const set = new Set(caps);
    return [...this.byName.values()].filter((t) => set.has(t.capability));
  }

  requireCapabilities(caps: Iterable<string>): void {
    for (const cap of caps) {
      const list = this.byCapability.get(cap);
      if (!list || list.length === 0) {
        throw new MissingCapabilityError(
          `required capability '${cap}' has no registered tool`,
        );
      }
    }
  }

  async call(
    capability: string,
    args: Record<string, unknown>,
    ctx: ToolContext,
    toolName?: string,
  ): Promise<unknown> {
    let tool: Tool | undefined;
    if (toolName !== undefined) {
      tool = this.byName.get(toolName);
      if (!tool) {
        throw new MissingCapabilityError(`no tool named '${toolName}' registered`);
      }
      if (tool.capability !== capability) {
        throw new MissingCapabilityError(
          `tool '${toolName}' has capability '${tool.capability}', but was called as '${capability}'`,
        );
      }
    } else {
      tool = this.get(capability);
      if (!tool) {
        throw new MissingCapabilityError(
          `no tool registered for capability '${capability}'`,
        );
      }
    }
    try {
      return await tool.handler(args, ctx);
    } catch (e) {
      if (e instanceof NemoIRRuntimeError) throw e;
      // Let AbortError pass through for clean cancellation semantics
      // (mirrors how WebLLM adapter's interrupt path handles AbortError).
      if (e instanceof DOMException && e.name === "AbortError") throw e;
      throw new ToolInvocationError(
        `tool '${tool.name}' (capability '${tool.capability}') failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
}
