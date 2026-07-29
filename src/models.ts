/**
 * NemoIR Web Runtime — model stage executor.
 *
 * Ports `ModelStageExecutor` from
 * `python/nemoir-runtime/src/nemoir_runtime/models.py`.
 *
 * The executor drives the model tool-call loop with bounded retries:
 * - Stage-output errors (invalid JSON, wrong schema) consume
 *   `maxModelRetries` (default 3 per stage).
 * - Tool-call errors (invalid args, unknown tool, policy denial) are
 *   corrective feedback and do NOT consume `maxModelRetries`; the sole
 *   bound is `maxToolRounds` (default 32).
 *
 * Supports two protocols:
 * - **native**: the adapter returns `ModelResponse.toolCalls` (used by
 *   Python-conformance fake adapters).
 * - **tagged-envelope**: the model returns content text containing a
 *   tagged JSON action `{ "kind": "tool_call", ... }` or
 *   `{ "kind": "final", "output": ... }` (the baseline for small WebLLM
 *   models that don't reliably support function-calling).
 *
 * The protocol is selected by `StageContext.options` — an explicit
 * `actionProtocol` field, not auto-detected (a stage output can
 * legitimately have `kind`/`output` fields).
 */

import { WRITE_TYPE_TO_JSON, getCapability } from "./capabilities.js";
import {
  ModelOutputValidationError,
  ModelProviderError,
  PolicyDeniedError,
  ToolInvocationError,
} from "./errors.js";
import {
  type ModelAdapter,
  type ModelResponse,
  type ModelToolCall,
  modelForStage,
  resolveReasoningMode,
  supportsStreaming,
} from "./model-contract.js";
import {
  type ModelRouter,
  type ModelRequest,
} from "./model-contract.js";
import { jsonrepair } from "jsonrepair";
import {
  type StageContext,
  type StageExecutor,
} from "./runtime.js";
import type { WriteSpec } from "./manifest.js";
import type { ModelStageOutputValidators } from "./runtime-types.js";
import type { Tool, ToolParamType } from "./tools.js";
import type { WorkflowEventEmitter } from "./events.js";

// ---------------------------------------------------------------------------
// Action protocol types
// ---------------------------------------------------------------------------

export type ActionProtocol = "native" | "tagged_envelope";

export type StageAction =
  | { kind: "final"; output: Record<string, unknown> }
  | { kind: "tool_call"; tool: string; args: Record<string, unknown> };

// ---------------------------------------------------------------------------
// Output schema + normalization helpers
// ---------------------------------------------------------------------------

export function outputSchemaForStage(stage: { id?: string; writes: readonly WriteSpec[] }): Record<string, unknown> {
  const properties: Record<string, unknown> = {};
  const required: string[] = [];
  for (const write of stage.writes) {
    const jsonType = WRITE_TYPE_TO_JSON[write.type];
    if (!jsonType) {
      throw new ModelOutputValidationError(
        `unsupported output write type '${write.type}' in stage '${stage.id ?? "unknown"}'`,
      );
    }
    properties[write.name] = jsonType;
    if (!write.optional) {
      required.push(write.name);
    }
  }
  const schema: Record<string, unknown> = {
    type: "object",
    properties,
    additionalProperties: false,
  };
  if (required.length > 0) {
    schema.required = required;
  }
  return schema;
}

export function normalizeStageOutput(
  stage: { id: string; writes: readonly WriteSpec[] },
  raw: Record<string, unknown>,
): Record<string, unknown> {
  const allowed = new Set(stage.writes.map((w) => w.name));
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) {
      throw new ModelOutputValidationError(
        `unknown output field '${key}' in stage '${stage.id}'`,
      );
    }
  }
  const result: Record<string, unknown> = {};
  for (const write of stage.writes) {
    let val = raw[write.name];
    // Normalize empty optional arrays to null
    if (
      write.optional &&
      Array.isArray(val) &&
      val.length === 0 &&
      write.type.endsWith("[]")
    ) {
      val = null;
    }
    if (val === undefined || val === null) {
      // json-typed writes may legitimately be null; treat null as present.
      if (!write.optional && !(val === null && write.type === "json")) {
        throw new ModelOutputValidationError(
          `missing required output field '${write.name}' in stage '${stage.id}'`,
        );
      }
      result[write.name] = null;
      continue;
    }
    result[write.name] = normalizeWriteValue(write, val, stage.id);
  }
  return result;
}

/**
 * Recursively check that a value is JSON-safe for model-output validation.
 * Cycle-safe (see `isJsonSafeValue`).
 */
function isModelJsonSafeValue(value: unknown, seen?: WeakSet<object>): boolean {
  if (value === null) return true;
  if (typeof value === "string") return true;
  if (typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    if (seen?.has(value)) return false;
    seen ??= new WeakSet();
    seen.add(value);
    return value.every((v) => isModelJsonSafeValue(v, seen));
  }
  if (typeof value === "object") {
    if (Object.prototype.toString.call(value) !== "[object Object]") return false;
    if (seen?.has(value)) return false;
    seen ??= new WeakSet();
    seen.add(value);
    return Object.values(value as Record<string, unknown>).every((v) =>
      isModelJsonSafeValue(v, seen),
    );
  }
  return false;
}

function normalizeWriteValue(
  write: WriteSpec,
  val: unknown,
  stageId: string,
): unknown {
  switch (write.type) {
    case "string":
      if (typeof val !== "string") {
        throw new ModelOutputValidationError(
          `expected string for '${write.name}' in stage '${stageId}', got ${typeof val}`,
        );
      }
      return val;
    case "bool":
      if (typeof val !== "boolean") {
        throw new ModelOutputValidationError(
          `expected boolean for '${write.name}' in stage '${stageId}', got ${typeof val}`,
        );
      }
      return val;
    case "number":
      if (typeof val === "boolean" || typeof val !== "number") {
        throw new ModelOutputValidationError(
          `expected number for '${write.name}' in stage '${stageId}', got ${typeof val}`,
        );
      }
      return val;
    case "string[]":
      if (!Array.isArray(val) || !val.every((v) => typeof v === "string")) {
        throw new ModelOutputValidationError(
          `expected string[] for '${write.name}' in stage '${stageId}'`,
        );
      }
      return [...val];
    case "json":
      // Recursively validate JSON-safe values (no Set, Map, Function, etc.).
      if (!isModelJsonSafeValue(val)) {
        throw new ModelOutputValidationError(
          `expected JSON-safe value for '${write.name}' in stage '${stageId}', got ${typeof val === "object" && val !== null ? Object.prototype.toString.call(val) : String(val)}`,
        );
      }
      return val;
    default:
      throw new ModelOutputValidationError(
        `unsupported write type '${write.type}' in stage '${stageId}'`,
      );
  }
}

// ---------------------------------------------------------------------------
// Tool schema helpers (OpenAI function-calling format)
// ---------------------------------------------------------------------------

export function toolResultToModelContent(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return value;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value) || typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

// ---------------------------------------------------------------------------
// Tool argument / schema helpers
// ---------------------------------------------------------------------------

function paramTypeToJsonSchema(ty: ToolParamType): Record<string, unknown> {
  switch (ty) {
    case "string":
      return { type: "string" };
    case "boolean":
      return { type: "boolean" };
    case "number":
      return { type: "number" };
    case "json":
      return {};
    case "string[]":
      return { type: "array", items: { type: "string" } };
    case "string[] | null":
      return { type: ["array", "null"], items: { type: "string" } };
  }
}

/** Build an OpenAI-style function-calling schema for a tool. */
export function toolJsonSchema(tool: Tool): Record<string, unknown> {
  const properties: Record<string, Record<string, unknown>> = {};
  const spec = getCapability(tool.capability);
  // Only truly required catalog params are marked required in the schema;
  // optional catalog params (e.g. http.fetch headers, body) are not.
  const catalogRequiredNames = new Set<string>();
  if (spec) {
    for (const p of spec.requiredParams) {
      if (p.required !== false) catalogRequiredNames.add(p.name);
    }
  }
  const required: string[] = [];
  for (const [name, ty] of Object.entries(tool.inputSchema)) {
    properties[name] = paramTypeToJsonSchema(ty);
    if (catalogRequiredNames.has(name)) required.push(name);
  }
  const schema: Record<string, unknown> = {
    type: "object",
    properties,
    additionalProperties: false,
  };
  if (required.length > 0) schema.required = required;
  return schema;
}

/** Human-readable description of a tool's arguments, for text prompts. */
function toolArgsDescription(tool: Tool): string {
  const spec = getCapability(tool.capability);
  const catalogRequiredNames = new Set<string>();
  if (spec) {
    for (const p of spec.requiredParams) {
      if (p.required !== false) catalogRequiredNames.add(p.name);
    }
  }
  const entries = Object.entries(tool.inputSchema).map(([name, ty]) => {
    const opt = catalogRequiredNames.has(name) ? "required" : "optional";
    return `"${name}" (${ty}, ${opt})`;
  });
  return entries.length > 0 ? `{ ${entries.join(", ")} }` : "{}";
}

/** Build a textual list of stage-visible tools for the tagged-envelope prompt. */
function toolsToPromptText(tools: readonly Tool[]): string {
  if (tools.length === 0) {
    return "No tools are available for this stage. Produce the final output directly.";
  }
  const lines = tools.map(
    (t) =>
      `- ${t.name} (${t.capability}): ${t.description}. Args: ${toolArgsDescription(t)}`,
  );
  return lines.join("\n");
}

/**
 * Validate model-supplied tool arguments against a tool's input schema.
 *
 * Mirrors Python `normalize_tool_args`: rejects unknown argument names and
 * missing catalog-required arguments. Tool handlers tolerate optional
 * parameters being absent.
 */
export function normalizeToolArgs(
  tool: Tool,
  rawArgs: Record<string, unknown>,
): Record<string, unknown> {
  const known = new Set(Object.keys(tool.inputSchema));
  for (const key of Object.keys(rawArgs)) {
    if (!known.has(key)) {
      throw new ModelOutputValidationError(
        `unknown argument '${key}' for tool '${tool.name}' (capability '${tool.capability}')`,
      );
    }
  }
  const spec = getCapability(tool.capability);
  if (spec) {
    for (const p of spec.requiredParams) {
      // Only truly required catalog params are mandatory; optional
      // params (e.g. http.fetch headers, body) can be absent.
      if (p.required === false) continue;
      const v = rawArgs[p.name];
      if (v === undefined || v === null) {
        throw new ModelOutputValidationError(
          `missing required argument '${p.name}' for tool '${tool.name}' (capability '${tool.capability}')`,
        );
      }
    }
  }
  return rawArgs;
}

// ---------------------------------------------------------------------------
// Retry message helpers
// ---------------------------------------------------------------------------

const INVALID_CONTENT_PREVIEW_MAX = 500;

interface OutputContractField {
  readonly name: string;
  readonly required: boolean;
  readonly schema: Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function outputContractFields(
  outputSchema: Record<string, unknown>,
): readonly OutputContractField[] {
  const rawProperties = isRecord(outputSchema.properties)
    ? outputSchema.properties
    : {};
  const required = new Set(
    Array.isArray(outputSchema.required)
      ? outputSchema.required.filter((name): name is string => typeof name === "string")
      : [],
  );

  return Object.entries(rawProperties).map(([name, schema]) => ({
    name,
    required: required.has(name),
    schema: isRecord(schema) ? schema : {},
  }));
}

function exampleValueForOutputField(schema: Record<string, unknown>): unknown {
  switch (schema.type) {
    case "string":
      return "your answer";
    case "boolean":
      return false;
    case "number":
      return 0;
    case "array":
      return ["your first item"];
    default:
      return null;
  }
}

/**
 * Explain output shape in concrete language instead of presenting a raw JSON
 * Schema document. Small local models regularly echo JSON Schema metadata
 * (`type`, `properties`, `required`) as if it were their answer.
 */
function outputContractText(
  outputSchema: Record<string, unknown>,
  useTaggedEnvelope: boolean,
): string {
  const fields = outputContractFields(outputSchema);
  const destination = useTaggedEnvelope
    ? 'inside the final envelope\'s "output" object'
    : "at the top level";

  if (fields.length === 0) {
    return `Return an empty JSON object ${destination}.`;
  }

  const required = fields.filter((field) => field.required).map((field) => field.name);
  const optional = fields.filter((field) => !field.required).map((field) => field.name);
  const example = Object.fromEntries(
    fields.map((field) => [field.name, exampleValueForOutputField(field.schema)]),
  );
  const quoteKeys = (keys: readonly string[]) => keys.map((key) => `"${key}"`).join(", ");

  const lines = [
    `The ONLY allowed output keys ${destination} are: ${quoteKeys(fields.map((field) => field.name))}.`,
  ];
  if (required.length > 0) lines.push(`Required keys: ${quoteKeys(required)}.`);
  if (optional.length > 0) lines.push(`Optional keys: ${quoteKeys(optional)}.`);
  lines.push(
    `Use actual answer values. Do NOT output a JSON Schema, type definitions, placeholders, or field names copied from the readable context.`,
  );
  lines.push(`Concrete JSON shape (replace every example value): ${JSON.stringify(example)}`);
  return lines.join("\n");
}

function stageRetryMessage(
  stageId: string,
  errorMsg: string,
  outputSchema: Record<string, unknown>,
  useTaggedEnvelope: boolean,
  invalidContent?: string | null,
): Record<string, unknown> {
  let content =
    `The previous response for stage '${stageId}' was invalid. Correct the errors and retry.\n\n` +
    `Error:\n${errorMsg}\n\n` +
    `Output contract:\n${outputContractText(outputSchema, useTaggedEnvelope)}\n\n`;
  if (useTaggedEnvelope) {
    content +=
      `Reply with ONLY {"kind":"final","output":{...}}. Apply the output contract only inside "output".\n`;
  } else {
    content += "Reply with ONLY one direct JSON object that follows the output contract.\n";
  }
  if (invalidContent) {
    const preview =
      invalidContent.length > INVALID_CONTENT_PREVIEW_MAX
        ? invalidContent.slice(0, INVALID_CONTENT_PREVIEW_MAX)
        : invalidContent;
    content += `\nYour previous output was invalid; do not repeat its shape:\n${preview}`;
  }
  return { role: "user", content };
}

function toolErrorContent(errorMsg: string): string {
  return JSON.stringify({ ok: false, error: errorMsg, retryable: true });
}

function canonicalToolCallId(tc: ModelToolCall, index: number): string {
  return tc.id || `call_${index}`;
}

// ---------------------------------------------------------------------------
// Tagged-envelope parsing
// ---------------------------------------------------------------------------

/**
 * Tolerantly extract the tagged envelope from content that may contain
 * leading reasoning prose, quoted JSON-like values, or trailing prose /
 * duplicate JSON blocks — common with thinking / small local models that
 * emit chain-of-thought before the envelope.
 *
 * Scans every top-level balanced `{...}` object in `content` (in order)
 * and returns the first one whose parsed form carries a `"kind"` key. This
 * is what lets a thinking model that writes, e.g. `{"input.eps": 0.02}` in
 * its reasoning still resolve to the trailing `{"kind":"final",...}`.
 *
 * Returns `null` if no such object is found.
 */
function extractFirstJsonObject(content: string): string | null {
  let depth = 0;
  let inStr = false;
  let escape = false;
  let start = -1;
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (inStr) {
      if (escape) {
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else if (ch === '"') {
        inStr = false;
      }
      continue;
    }
    if (ch === '"') {
      inStr = true;
    } else if (ch === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}") {
      if (depth === 0) continue; // stray '}' in prose; ignore
      depth--;
      if (depth === 0 && start !== -1) {
        const candidate = content.slice(start, i + 1);
        // Only accept objects that look like a tagged envelope. Cheap string
        // pre-check avoids parsing large non-envelope prose objects.
        if (candidate.includes('"kind"')) {
          return candidate;
        }
        start = -1; // keep scanning subsequent top-level objects
      }
    }
  }
  // Unterminated object: the model truncated the trailing '}' (or stopped
  // mid-string). If the partial object contains "kind", auto-close it.
  // This is very common with small/streaming models that end generation
  // right after the last value.
  if (depth > 0 && start !== -1) {
    const partial = content.slice(start);
    if (partial.includes('"kind"')) {
      let fixup = partial;
      if (inStr) fixup += '"'; // close an unterminated string value
      fixup += "}".repeat(depth);
      return fixup;
    }
  }
  return null;
}

/**
 * Tolerantly extract the first balanced JSON object without requiring a
 * tagged-envelope key. Used only for model stages with no callable tools,
 * where a direct JSON object is unambiguous and avoids imposing envelope
 * syntax on smaller local models.
 */
function extractFirstPlainJsonObject(content: string): string | null {
  let depth = 0;
  let inStr = false;
  let escape = false;
  let start = -1;
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (inStr) {
      if (escape) {
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else if (ch === '"') {
        inStr = false;
      }
      continue;
    }
    if (ch === '"') {
      inStr = true;
    } else if (ch === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}") {
      if (depth === 0) continue;
      depth--;
      if (depth === 0 && start !== -1) {
        return content.slice(start, i + 1);
      }
    }
  }
  if (depth > 0 && start !== -1) {
    let fixup = content.slice(start);
    if (inStr) fixup += '"';
    fixup += "}".repeat(depth);
    return fixup;
  }
  return null;
}

/**
 * Parse model JSON. A strict `JSON.parse` is attempted first so valid JSON is
 * never altered; only on failure is a repair pass applied. WebLLM's grammar
 * constraint (set in `webllm.ts` for tool-less stages) already guarantees
 * structural validity for `cs1k` models, so the repair path is a safety net
 * for non-grammar models, tool-envelope stages, and the rare malformed edge.
 *
 * `jsonrepair` handles the full class of small-model mistakes (missing
 * commas, quotes, brackets, single quotes, truncated JSON, trailing commas,
 * Python `None/True/False`, escaped strings, code fences). It supersedes the
 * previous comma-only scanner.
 */
function parseJsonTolerantly(json: string, stageId: string): unknown {
  try {
    return JSON.parse(json);
  } catch (firstError) {
    let repaired: string;
    try {
      repaired = jsonrepair(json);
    } catch {
      throw new ModelOutputValidationError(
        `model returned invalid JSON in stage '${stageId}': ${firstError instanceof Error ? firstError.message : String(firstError)}`,
      );
    }
    try {
      return JSON.parse(repaired);
    } catch (repairError) {
      throw new ModelOutputValidationError(
        `model returned invalid JSON in stage '${stageId}': ${firstError instanceof Error ? firstError.message : String(firstError)}` +
          ` (jsonrepair: ${repairError instanceof Error ? repairError.message : String(repairError)})`,
      );
    }
  }
}

function parsePlainStageOutput(content: string, stageId: string): Record<string, unknown> {
  const json = extractFirstPlainJsonObject(content) ?? content;
  const parsed = parseJsonTolerantly(json, stageId);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ModelOutputValidationError(
      `model returned ${typeof parsed} instead of object in stage '${stageId}'`,
    );
  }

  const obj = parsed as Record<string, unknown>;
  // Continue to accept a correctly tagged final envelope for backward
  // compatibility when the stage itself has no tools.
  if (obj.kind === "final") {
    const output = obj.output;
    if (typeof output !== "object" || output === null || Array.isArray(output)) {
      throw new ModelOutputValidationError(
        `tagged envelope 'final' output must be an object in stage '${stageId}'`,
      );
    }
    return output as Record<string, unknown>;
  }
  if ("kind" in obj) {
    throw new ModelOutputValidationError(
      `model returned tagged action '${String(obj.kind)}' in tool-less stage '${stageId}'; expected a final JSON object`,
    );
  }
  return obj;
}

function parseTaggedEnvelope(content: string, stageId: string): StageAction {
  // Small models often emit the envelope followed by trailing prose or a
  // duplicate JSON block. Try strict parse first; if it fails, attempt to
  // extract the first balanced JSON object starting at the first '{' that
  // carries a "kind" field.
  const json = extractFirstJsonObject(content) ?? content;
  const parsed = parseJsonTolerantly(json, stageId);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ModelOutputValidationError(
      `model returned ${typeof parsed} instead of object in stage '${stageId}'`,
    );
  }
  const obj = parsed as Record<string, unknown>;
  const kind = obj.kind;
  if (kind === "final") {
    const output = obj.output;
    if (typeof output !== "object" || output === null || Array.isArray(output)) {
      throw new ModelOutputValidationError(
        `tagged envelope 'final' output must be an object in stage '${stageId}'`,
      );
    }
    return { kind: "final", output: output as Record<string, unknown> };
  }
  if (kind === "tool_call") {
    const tool = obj.tool;
    const args = obj.args;
    if (typeof tool !== "string") {
      throw new ModelOutputValidationError(
        `tagged envelope 'tool_call' must have a string 'tool' field in stage '${stageId}'`,
      );
    }
    if (typeof args !== "object" || args === null || Array.isArray(args)) {
      throw new ModelOutputValidationError(
        `tagged envelope 'tool_call' args must be an object in stage '${stageId}'`,
      );
    }
    return { kind: "tool_call", tool, args: args as Record<string, unknown> };
  }
  throw new ModelOutputValidationError(
    `model returned unknown envelope kind '${kind}' in stage '${stageId}'; expected 'final' or 'tool_call'`,
  );
}

// ---------------------------------------------------------------------------
// ModelStageExecutor
// ---------------------------------------------------------------------------

export class ModelStageExecutor implements StageExecutor {
  private readonly model: ModelAdapter | ModelRouter;
  private readonly tools: import("./tools.js").ToolRegistry;
  private readonly maxToolRounds: number | null;
  private readonly actionProtocol: ActionProtocol;
  private readonly modelOutputValidators?: ModelStageOutputValidators;

  constructor(opts: {
    model: ModelAdapter | ModelRouter;
    tools: import("./tools.js").ToolRegistry;
    maxToolRounds?: number | null;
    actionProtocol?: ActionProtocol;
    modelOutputValidators?: ModelStageOutputValidators;
  }) {
    this.model = opts.model;
    this.tools = opts.tools;
    this.maxToolRounds = opts.maxToolRounds ?? 32;
    this.actionProtocol = opts.actionProtocol ?? "native";
    this.modelOutputValidators = opts.modelOutputValidators;
  }

  async execute(ctx: StageContext): Promise<Record<string, unknown>> {
    const adapter = modelForStage(this.model, ctx.stage.id);

    // Resolve reasoning mode
    const effectiveReasoning = resolveReasoningMode(
      (adapter as { reasoning?: string }).reasoning ?? "none",
      ctx.options.reasoning,
    );

    const maxRetries = ctx.options.maxModelRetries;
    let retryCount = 0;

    const outputSchema = outputSchemaForStage(ctx.stage);
    const stageTools = this.tools.toolsForCapabilities(ctx.allowedCapabilities);
    const toolSchemas = stageTools.map((t) => ({
      type: "function",
      function: {
        name: t.name,
        description: t.description,
        parameters: toolJsonSchema(t),
      },
    }));

    // Tagged envelopes are needed only for stages that can call tools. For a
    // tool-less stage, a direct JSON object is unambiguous and substantially
    // more reliable for small local WebLLM models.
    const protocol: ActionProtocol = this.actionProtocol;
    const useTaggedEnvelope =
      protocol === "tagged_envelope" && stageTools.length > 0;

    const messages: Record<string, unknown>[] = this.buildInitialMessages(
      ctx,
      outputSchema,
      useTaggedEnvelope,
      stageTools,
    );

    const emitter = ctx.eventEmitter;
    const useStreaming =
      emitter !== null &&
      emitter.hasSink &&
      supportsStreaming(adapter);

    let toolRounds = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const request: ModelRequest = {
        stageId: ctx.stage.id,
        messages: [...messages],
        tools: toolSchemas,
        outputSchema,
        options: { reasoning: effectiveReasoning },
        signal: ctx.options.signal,
      };

      let response: ModelResponse;
      try {
        if (useStreaming && emitter) {
          response = await this.streamAdapterResponse(adapter, request, ctx, emitter);
        } else {
          response = await adapter.complete(request);
          if (emitter) {
            await emitter.emit("model_completed", { stageId: ctx.stage.id });
          }
        }
      } catch (e) {
        if (e instanceof ModelOutputValidationError) {
          if (retryCount >= maxRetries) throw e;
          retryCount++;
          await this.emitModelRetry(emitter, ctx.stage.id, String(e), "tool_call_parse", retryCount, maxRetries);
          messages.push(
            stageRetryMessage(ctx.stage.id, String(e), outputSchema, useTaggedEnvelope),
          );
          continue;
        }
        throw e;
      }

      // --- Native tool calls ---
      if (protocol === "native" && response.toolCalls && response.toolCalls.length > 0) {
        if (this.maxToolRounds !== null && toolRounds >= this.maxToolRounds) {
          throw new ModelOutputValidationError(
            `stage '${ctx.stage.id}' exceeded maxToolRounds=${this.maxToolRounds}`,
          );
        }
        toolRounds++;
        messages.push(this.assistantToolCallMessage(response));

        let hadToolError = false;
        let i = 0;
        for (const tc of response.toolCalls) {
          const tcId = canonicalToolCallId(tc, i++);
          try {
            const tool = this.tools.getByName(tc.name);
            if (!tool) {
              throw new ModelOutputValidationError(
                `model requested unknown tool '${tc.name}' in stage '${ctx.stage.id}'`,
              );
            }
            if (!ctx.allowedCapabilities.has(tool.capability)) {
              throw new ModelOutputValidationError(
                `tool '${tc.name}' has capability '${tool.capability}' which is not allowed in stage '${ctx.stage.id}'`,
              );
            }
            const result = await ctx.callTool(tool.capability, normalizeToolArgs(tool, { ...tc.arguments }), tool.name);
            messages.push(this.toolResultMessage(tcId, toolResultToModelContent(result)));
          } catch (e) {
            if (
              e instanceof ModelOutputValidationError ||
              e instanceof ToolInvocationError ||
              e instanceof PolicyDeniedError
            ) {
              hadToolError = true;
              messages.push(this.toolResultMessage(tcId, toolErrorContent(String(e))));
            } else {
              throw e;
            }
          }
        }

        if (hadToolError && emitter) {
          await this.emitModelRetry(
            emitter,
            ctx.stage.id,
            "One or more tool calls failed; feedback sent to model",
            "tool_call",
            toolRounds,
            this.maxToolRounds ?? -1,
          );
        }
        // Loop back for more tool calls or final output
        continue;
      }

      // --- Final output (content-only response) ---
      // Empty content is a provider-level failure, not a correctable schema
      // error. Retrying it sends the error text back to the model, which small
      // local models echo or loop on degenerately. Fail the run immediately.
      if (!response.content) {
        throw new ModelProviderError(
          `model returned empty content in stage '${ctx.stage.id}'`,
        );
      }

      let parsed: unknown;
      // Tool-enabled tagged stages retain the explicit action envelope so a
      // model can unambiguously request a tool. Tool-less stages instead use
      // a direct JSON object: there is no possible tool-call branch, and this
      // avoids an unnecessary format burden for small local models.
      if (useTaggedEnvelope) {
        let action: StageAction;
        try {
          action = parseTaggedEnvelope(response.content, ctx.stage.id);
        } catch (e) {
          if (e instanceof ModelOutputValidationError) {
            if (retryCount >= maxRetries) throw e;
            retryCount++;
            await this.emitModelRetry(emitter, ctx.stage.id, String(e), "stage_output", retryCount, maxRetries);
            messages.push(stageRetryMessage(ctx.stage.id, String(e), outputSchema, useTaggedEnvelope, response.content));
            continue;
          }
          throw e;
        }
        if (action.kind === "tool_call") {
          if (this.maxToolRounds !== null && toolRounds >= this.maxToolRounds) {
            throw new ModelOutputValidationError(
              `stage '${ctx.stage.id}' exceeded maxToolRounds=${this.maxToolRounds}`,
            );
          }
          toolRounds++;
          messages.push({ role: "assistant", content: response.content });
          let hadToolError = false;
          try {
            const tool = this.tools.getByName(action.tool);
            if (!tool) {
              throw new ModelOutputValidationError(
                `model requested unknown tool '${action.tool}' in stage '${ctx.stage.id}'`,
              );
            }
            if (!ctx.allowedCapabilities.has(tool.capability)) {
              throw new ModelOutputValidationError(
                `tool '${action.tool}' has capability '${tool.capability}' which is not allowed in stage '${ctx.stage.id}'`,
              );
            }
            const result = await ctx.callTool(tool.capability, normalizeToolArgs(tool, { ...action.args }), tool.name);
            messages.push({
              role: "user",
              content: `Tool '${action.tool}' returned:\n${toolResultToModelContent(result)}`,
            });
          } catch (e) {
            if (
              e instanceof ModelOutputValidationError ||
              e instanceof ToolInvocationError ||
              e instanceof PolicyDeniedError
            ) {
              hadToolError = true;
              messages.push({
                role: "user",
                content: `Tool '${action.tool}' failed: ${String(e)}. Correct the arguments and retry, or produce the final output.`,
              });
            } else {
              throw e;
            }
          }
          if (hadToolError && emitter) {
            await this.emitModelRetry(
              emitter,
              ctx.stage.id,
              "One or more tool calls failed; feedback sent to model",
              "tool_call",
              toolRounds,
              this.maxToolRounds ?? -1,
            );
          }
          continue;
        }
        // kind === "final": use action.output as the parsed output.
        parsed = action.output;
      } else {
        try {
          parsed = parsePlainStageOutput(response.content, ctx.stage.id);
        } catch (e) {
          if (e instanceof ModelOutputValidationError) {
            if (retryCount >= maxRetries) throw e;
            retryCount++;
            await this.emitModelRetry(emitter, ctx.stage.id, String(e), "stage_output", retryCount, maxRetries);
            messages.push(stageRetryMessage(ctx.stage.id, String(e), outputSchema, useTaggedEnvelope, response.content));
            continue;
          }
          throw e;
        }
      }

      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        const msg = `model returned ${typeof parsed} instead of object in stage '${ctx.stage.id}'`;
        const err = new ModelOutputValidationError(msg);
        if (retryCount >= maxRetries) throw err;
        retryCount++;
        await this.emitModelRetry(emitter, ctx.stage.id, msg, "stage_output", retryCount, maxRetries);
        messages.push(stageRetryMessage(ctx.stage.id, msg, outputSchema, useTaggedEnvelope, response.content));
        continue;
      }

      try {
        const normalized = normalizeStageOutput(ctx.stage, parsed as Record<string, unknown>);
        const semanticError = await this.semanticValidationError(ctx, normalized);
        if (semanticError) {
          const err = new ModelOutputValidationError(
            `semantic output validation failed in stage '${ctx.stage.id}': ${semanticError}`,
          );
          if (retryCount >= maxRetries) throw err;
          retryCount++;
          await this.emitModelRetry(
            emitter,
            ctx.stage.id,
            String(err),
            "semantic_output",
            retryCount,
            maxRetries,
          );
          messages.push(
            stageRetryMessage(
              ctx.stage.id,
              String(err),
              outputSchema,
              useTaggedEnvelope,
              response.content,
            ),
          );
          continue;
        }
        return normalized;
      } catch (e) {
        if (e instanceof ModelOutputValidationError) {
          if (retryCount >= maxRetries) throw e;
          retryCount++;
          await this.emitModelRetry(emitter, ctx.stage.id, String(e), "stage_output", retryCount, maxRetries);
          messages.push(
            stageRetryMessage(ctx.stage.id, String(e), outputSchema, useTaggedEnvelope, response.content),
          );
          continue;
        }
        throw e;
      }
    }
  }

  /**
   * Run an optional consumer-provided semantic validator after the model
   * output has passed the stage's structural schema checks. Returning an
   * error string here causes the caller's existing model retry loop to feed
   * that correction back to the model.
   */
  private async semanticValidationError(
    ctx: StageContext,
    output: Readonly<Record<string, unknown>>,
  ): Promise<string | null> {
    const validator = this.modelOutputValidators?.[ctx.stage.id];
    if (!validator) return null;

    const result = await validator(output, {
      stageId: ctx.stage.id,
      inputs: ctx.inputs,
      readableContext: ctx.readableContext,
    });
    if (result === null || result === undefined) return null;

    const errors = (typeof result === "string" ? [result] : result)
      .filter((error): error is string => typeof error === "string")
      .map((error) => error.trim())
      .filter(Boolean);
    return errors.length > 0 ? errors.join("; ") : null;
  }

  private buildInitialMessages(
    ctx: StageContext,
    outputSchema: Record<string, unknown>,
    useTaggedEnvelope: boolean,
    stageTools: readonly Tool[],
  ): Record<string, unknown>[] {
    let systemContent =
      "You are executing one NemoIR workflow stage. Follow the stage prompt. " +
      "Use only the supplied tools when needed. " +
      "Do not expose hidden chain-of-thought.";

    if (useTaggedEnvelope) {
      systemContent +=
        "\n\nYou communicate using a tagged JSON envelope. The 'output' field of the final envelope must contain the actual values for the stage output (NOT the schema itself).\n" +
        "When you want to call a tool, respond with ONLY: " +
        '{"kind":"tool_call","tool":"<name>","args":{...}}\n' +
        "When the stage is complete, respond with ONLY: " +
        '{"kind":"final","output":{...}}\n' +
        "The 'output' must be a JSON object whose keys are the field names and values are the actual stage results.\n" +
        "Example: if the required output schema is " +
        '{"type":"object","properties":{"score":{"type":"number"}},"required":["score"]} ' +
        'and the answer is 5, respond with ONLY: ' +
        '{"kind":"final","output":{"score":5}}\n' +
        "Do not include any prose, explanations, or schema definitions outside the JSON envelope.\n\n" +
        "Available tools:\n" + toolsToPromptText(stageTools);
    } else {
      systemContent +=
        "\n\nNo callable tools are available for this stage. Respond with ONLY a direct JSON object matching the required output schema. Do not use a {\"kind\":...,\"output\":...} envelope and do not include prose outside the JSON object.";
    }

    const finalInstruction = useTaggedEnvelope
      ? "When complete, respond with ONLY {\"kind\":\"final\",\"output\":{...}}.\n"
      : "When complete, respond with ONLY one direct JSON object.\n";
    const outputContract = outputContractText(outputSchema, useTaggedEnvelope);

    const userContent =
      `Workflow: ${ctx.workflowId}\n` +
      `Stage: ${ctx.stage.id}\n\n` +
      `Stage prompt:\n${ctx.stage.prompt}\n\n` +
      `Readable context:\n${JSON.stringify(ctx.readableContext, null, 2)}\n\n` +
      `Allowed capabilities:\n${JSON.stringify([...ctx.allowedCapabilities])}\n\n` +
      finalInstruction +
      `Output contract (separate from readable context):\n${outputContract}`;

    return [
      { role: "system", content: systemContent },
      { role: "user", content: userContent },
    ];
  }

  private async emitModelRetry(
    emitter: WorkflowEventEmitter | null,
    stageId: string,
    errorMsg: string,
    category: string,
    attempt: number,
    maxRetries: number,
  ): Promise<void> {
    if (!emitter) return;
    await emitter.emit("model_retry", {
      stageId,
      error: errorMsg,
      metadata: { attempt, maxRetries, category },
    });
  }

  private async streamAdapterResponse(
    adapter: ModelAdapter,
    request: ModelRequest,
    ctx: StageContext,
    emitter: WorkflowEventEmitter,
  ): Promise<ModelResponse> {
    if (!adapter.stream) {
      // Fall back to complete() if streaming not available
      const resp = await adapter.complete(request);
      await emitter.emit("model_completed", { stageId: ctx.stage.id });
      return resp;
    }
    let finalResponse: ModelResponse | null = null;
    for await (const chunk of adapter.stream(request)) {
      if (chunk.kind === "delta") {
        await emitter.emit("model_delta", {
          stageId: ctx.stage.id,
          channel: chunk.channel ?? null,
          text: chunk.text ?? null,
        });
      } else if (chunk.kind === "completed") {
        finalResponse = chunk.response ?? null;
        await emitter.emit("model_completed", { stageId: ctx.stage.id });
      }
    }
    if (!finalResponse) {
      throw new ModelOutputValidationError(
        `streaming adapter returned no completed chunk for stage '${ctx.stage.id}'`,
      );
    }
    return finalResponse;
  }

  private assistantToolCallMessage(response: ModelResponse): Record<string, unknown> {
    const toolCallsList = (response.toolCalls ?? []).map((tc) => ({
      id: tc.id,
      type: "function",
      function: { name: tc.name, arguments: JSON.stringify(tc.arguments) },
    }));
    return { role: "assistant", tool_calls: toolCallsList };
  }

  private toolResultMessage(toolCallId: string, content: string): Record<string, unknown> {
    return { role: "tool", tool_call_id: toolCallId, content };
  }
}
