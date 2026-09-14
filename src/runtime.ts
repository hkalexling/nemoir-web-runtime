/**
 * NemoIR Web Runtime — WorkflowRuntime state machine + policy engine.
 *
 * Ports `python/nemoir-runtime/src/nemoir_runtime/runtime.py`:
 * `WorkflowRuntime.run()`, `_enforce_and_call_with_policies`, read
 * resolution, output validation, optional-array normalization, transition
 * selection, and async-iterable `stream()`.
 *
 * Design note: `user.confirm` returns `Promise<boolean>` (not a sync
 * bool), so policy enforcement is async — a clean browser adaptation of
 * the Python runtime's synchronous `before`-policy check.
 */

import {
  type CapabilityParamType,
  getCapability,
} from "./capabilities.js";
import {
  DataUnavailableError,
  MaxStepsExceededError,
  MissingCapabilityError,
  NemoIRRuntimeError,
  NoTransitionMatchedError,
  PolicyDeniedError,
  PolicyEvaluationError,
  StageOutputValidationError,
  WorkflowValidationError,
} from "./errors.js";
import {
  WorkflowEventEmitter,
  type WorkflowEvent,
  type WorkflowEventSink,
} from "./events.js";
import {
  type PolicyRefContext,
  evalExpr,
  evaluateGuard,
  resolveGuardRef,
  resolvePolicyRef,
} from "./evaluator.js";
import {
  type PolicySpec,
  type RequiredCapabilitySpec,
  type StageSpec,
  type TriggerSpec,
  type WorkflowManifest,
} from "./manifest.js";
import { type RunOptions, type WorkflowResult, resolveRunOptions } from "./runtime-types.js";
import { type ToolContext, type ToolRegistry } from "./tools.js";
import {
  type NoOpTraceRecorder,
  TraceRecorder,
  resolveRecorder,
} from "./trace.js";

// ---------------------------------------------------------------------------
// Stage execution boundary
// ---------------------------------------------------------------------------

export interface StageContext {
  readonly workflowId: string;
  readonly stage: StageSpec;
  readonly inputs: Record<string, unknown>;
  readonly readableContext: Record<string, unknown>;
  readonly allowedCapabilities: ReadonlySet<string>;
  readonly options: RunOptions;
  readonly callTool: (
    capability: string,
    args: Record<string, unknown>,
    toolName?: string,
  ) => Promise<unknown>;
  readonly eventEmitter: WorkflowEventEmitter | null;
  /**
   * NemoTrace audit recorder (Phase 1). Null/undefined disables tracing;
   * the runtime substitutes a no-op so execution paths stay identical.
   */
  readonly traceRecorder?: TraceRecorder | NoOpTraceRecorder | null;
}

export interface StageExecutor {
  execute(ctx: StageContext): Promise<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Read display key (for readable context)
// ---------------------------------------------------------------------------

export function readDisplayKey(ref: { kind: string; name?: string; node?: string; field?: string }): string {
  if (ref.kind === "input") return `input.${ref.name}`;
  if (ref.kind === "node_output") return `${ref.node}.${ref.field}`;
  return `unknown.${ref.name}`;
}

// ---------------------------------------------------------------------------
// Output validation + type checking
// ---------------------------------------------------------------------------

/**
 * Recursively check that a value is JSON-safe: plain objects (not Set,
 * Map, Date, etc.), arrays, strings, finite numbers, booleans, and null.
 *
 * Shared by output validation and browser-native tools
 * (`browser.storage.write` values, `browser.js.run` results) so the
 * JSON-safe contract is enforced at the tool boundary, not only at
 * stage-write validation.
 *
 * Cycle-safe: tracks visited objects in a WeakSet so a cyclic value
 * returns `false` rather than overflowing the stack.
 */
function hasLoneSurrogate(value: string): boolean {
  // Lone surrogates are invalid UTF-8 / I-JSON. Detect unmatched lead/trail.
  for (let i = 0; i < value.length; i += 1) {
    const cu = value.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      // Lead surrogate must be followed by trail.
      if (i + 1 >= value.length || value.charCodeAt(i + 1) < 0xdc00 || value.charCodeAt(i + 1) > 0xdfff) {
        return true;
      }
      i += 1; // consume trail
    } else if (cu >= 0xdc00 && cu <= 0xdfff) {
      return true; // trail without lead
    }
  }
  return false;
}

export function isJsonSafeValue(value: unknown, seen?: WeakSet<object>): boolean {
  if (value === null) return true;
  if (typeof value === "string") return !hasLoneSurrogate(value);
  if (typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    if (seen?.has(value)) return false;
    seen ??= new WeakSet();
    seen.add(value);
    return value.every((v) => isJsonSafeValue(v, seen));
  }
  if (typeof value === "object") {
    // Only plain objects — reject Set, Map, Date, class instances, etc.
    if (Object.prototype.toString.call(value) !== "[object Object]") return false;
    if (seen?.has(value)) return false;
    seen ??= new WeakSet();
    seen.add(value);
    const entries = Object.entries(value as Record<string, unknown>);
    return entries.every(
      ([k, v]) => !hasLoneSurrogate(k) && isJsonSafeValue(v, seen),
    );
  }
  return false;
}

function validateWriteType(
  value: unknown,
  writeType: string,
  fieldName: string,
  stageId: string,
): void {
  // The web runtime has no filesystem: path values are opaque strings (the
  // same JSON form Python's ``pathlib.Path`` outputs serialize to). Compiled
  // web apps still reject path writes in the IR validator; this branch exists
  // so browser taped replay of a Python-targeted trace can execute stages
  // that declare path outputs.
  if (writeType === "string" || writeType === "path") {
    if (typeof value !== "string") {
      throw new StageOutputValidationError(
        `Stage '${stageId}' output field '${fieldName}': expected string, got ${typeof value}`,
      );
    }
    if (hasLoneSurrogate(value)) {
      throw new StageOutputValidationError(
        `Stage '${stageId}' output field '${fieldName}': string contains invalid Unicode (lone surrogate)`,
      );
    }
  } else if (writeType === "bool") {
    if (typeof value !== "boolean") {
      throw new StageOutputValidationError(
        `Stage '${stageId}' output field '${fieldName}': expected boolean, got ${typeof value}`,
      );
    }
  } else if (writeType === "number") {
    // accept number, reject bool (bool is not a number in this context)
    if (typeof value === "boolean" || typeof value !== "number") {
      throw new StageOutputValidationError(
        `Stage '${stageId}' output field '${fieldName}': expected number, got ${typeof value}`,
      );
    }
  } else if (writeType === "string[]") {
    if (!Array.isArray(value)) {
      throw new StageOutputValidationError(
        `Stage '${stageId}' output field '${fieldName}': expected array, got ${typeof value}`,
      );
    }
    if (!value.every((v) => typeof v === "string")) {
      throw new StageOutputValidationError(
        `Stage '${stageId}' output field '${fieldName}': expected string[] but contains non-string elements`,
      );
    }
    if (value.some((v) => hasLoneSurrogate(v as string))) {
      throw new StageOutputValidationError(
        `Stage '${stageId}' output field '${fieldName}': string contains invalid Unicode (lone surrogate)`,
      );
    }
  } else if (writeType === "json") {
    // Recursively validate that the value is JSON-safe (plain objects,
    // arrays, primitives, and null — no Set, Map, Function, etc.).
    if (!isJsonSafeValue(value)) {
      throw new StageOutputValidationError(
        `Stage '${stageId}' output field '${fieldName}': expected JSON-safe value, got ${typeof value === "object" && value !== null ? Object.prototype.toString.call(value) : String(value)}`,
      );
    }
  } else {
    throw new StageOutputValidationError(
      `Stage '${stageId}' output field '${fieldName}': unsupported type '${writeType}'`,
    );
  }
}

function validateOutput(stage: StageSpec, output: Record<string, unknown>): void {
  const allowedNames = new Set(stage.writes.map((w) => w.name));
  for (const key of Object.keys(output)) {
    if (!allowedNames.has(key)) {
      throw new StageOutputValidationError(
        `Stage '${stage.id}' returned unknown output field '${key}'`,
      );
    }
  }
  for (const write of stage.writes) {
    const val = output[write.name];
    // json-typed writes may legitimately be null; treat null as a present
    // value for json, not as a missing field.
    if (!write.optional && (val === undefined || (val === null && write.type !== "json"))) {
      throw new StageOutputValidationError(
        `Stage '${stage.id}' is missing required output field '${write.name}'`,
      );
    }
    if (val !== undefined && val !== null) {
      validateWriteType(val, write.type, write.name, stage.id);
    } else if (val === null && write.type !== "json") {
      // null is only valid for json writes; skip type-check for null
    } else if (val === null) {
      // json-typed null — already validated as present above
    }
  }
}

/**
 * Treat empty lists for optional array outputs as null.
 *
 * LLMs often emit `[]` for optional arrays when they mean "no items".
 * This normalization prevents `has_value` guards from matching on empty
 * collections, which would cause unintended loops.
 */
function normalizeOptionalEmptyArrays(
  stage: StageSpec,
  output: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...output };
  for (const write of stage.writes) {
    if (!write.optional) continue;
    if (!write.type.endsWith("[]")) continue;
    const val = result[write.name];
    if (Array.isArray(val) && val.length === 0) {
      result[write.name] = null;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Read resolution
// ---------------------------------------------------------------------------

function resolveReads(
  stage: StageSpec,
  inputs: Record<string, unknown>,
  stageOutputs: Record<string, Record<string, unknown>>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const read of stage.reads) {
    const key = readDisplayKey(read.ref);
    const value = resolveGuardRef(read.ref, inputs, stageOutputs);
    if (read.optional) {
      result[key] = value;
    } else {
      if (value === null || value === undefined) {
        throw new DataUnavailableError(
          `Stage '${stage.id}': required read '${key}' is not available`,
        );
      }
      result[key] = value;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Transition selection
// ---------------------------------------------------------------------------

function selectTransition(
  stage: StageSpec,
  inputs: Record<string, unknown>,
  stageOutputs: Record<string, Record<string, unknown>>,
  recorder?: TraceRecorder | NoOpTraceRecorder | null,
  stageVisitId?: string,
): { to: string; priority: number; reason: string } {
  const rec = resolveRecorder(recorder);
  const sorted = [...stage.transitions].sort((a, b) => a.priority - b.priority);
  const candidates: { to: string; priority: number; reason: string; matched: boolean }[] = [];
  for (const trans of sorted) {
    const matched = evaluateGuard(trans.guard, inputs, stageOutputs);
    candidates.push({ to: trans.to, priority: trans.priority, reason: trans.reason, matched });
    if (matched) {
      if (stageVisitId) rec.recordTransitionEvaluation(stageVisitId, candidates);
      return trans;
    }
  }
  throw new NoTransitionMatchedError(`Stage '${stage.id}': no transition matched`);
}

// ---------------------------------------------------------------------------
// Policy enforcement
// ---------------------------------------------------------------------------

/**
 * Generate a random run ID (UUID v4 hex).
 * Falls back to crypto.randomUUID() if available, else Math.random.
 */
function generateRunId(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID().replace(/-/g, "");
  }
  return Array.from({ length: 32 }, () =>
    Math.floor(Math.random() * 16).toString(16),
  ).join("");
}

/**
 * Bind trigger arguments to bound variables.
 * Mirrors `WorkflowRuntime._bind_trigger_args`.
 */
function bindTriggerArgs(
  trigger: TriggerSpec,
  args: Record<string, unknown>,
  policyId: string,
  capability: string,
): Record<string, unknown> {
  const bound: Record<string, unknown> = {};
  const spec = getCapability(capability);
  const boundTypes: Record<string, CapabilityParamType> = {};
  if (spec) {
    for (const p of spec.requiredParams) {
      boundTypes[p.name] = p.type;
    }
  }
  for (const [boundVar, argName] of trigger.bind) {
    if (!(argName in args)) {
      throw new PolicyEvaluationError(
        `Policy '${policyId}': trigger-bound argument '${argName}' is missing from capability '${capability}' call args`,
      );
    }
    bound[boundVar] = args[argName];
  }
  return bound;
}

/**
 * Resolve args for a before-policy required capability call.
 */
function resolveRequiredArgs(
  req: RequiredCapabilitySpec,
  inputs: Record<string, unknown>,
  boundArgs: Record<string, unknown>,
  policyId: string,
  capability: string,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [argName, ref] of req.args) {
    result[argName] = resolvePolicyRef(ref, { inputs, boundArgs, policyId, capability });
  }
  return result;
}

/**
 * Check that all catalog-required args are present for a policy-required call.
 */
function checkRequiredArgsPresent(
  reqCapability: string,
  reqArgs: Record<string, unknown>,
  policyId: string,
  capability: string,
): void {
  const spec = getCapability(reqCapability);
  if (!spec) {
    throw new PolicyEvaluationError(
      `Policy '${policyId}': required capability '${reqCapability}' is not in the catalog`,
    );
  }
  for (const param of spec.requiredParams) {
    // Skip optional catalog params — only truly required params must be bound.
    if (param.required === false) continue;
    if (reqArgs[param.name] === undefined || reqArgs[param.name] === null) {
      throw new PolicyEvaluationError(
        `Policy '${policyId}': required capability '${reqCapability}' is missing catalog-required argument '${param.name}' for original capability '${capability}'`,
      );
    }
  }
}

function sandboxApprovalMessage(args: Record<string, unknown>): string {
  const code = typeof args.code === "string" ? args.code : "";
  return [
    "Run sandboxed JavaScript?",
    "It receives only this workflow stage's declared JSON input. Network APIs are restricted by CSP; host-page, host-origin storage, and NemoIR tool access are not exposed.",
    "",
    "Source:",
    code,
  ].join("\n");
}

function safeResultPreview(value: unknown): string | null {
  const MAX = 200;
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") {
    return value.length > MAX ? value.slice(0, MAX) + "..." : value;
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (Array.isArray(value) || typeof value === "object") {
    const s = JSON.stringify(value);
    return s.length > MAX ? s.slice(0, MAX) + "..." : s;
  }
  return typeof value;
}

// ---------------------------------------------------------------------------
// WorkflowRuntime
// ---------------------------------------------------------------------------

export class WorkflowRuntime {
  private readonly manifest: WorkflowManifest;
  private readonly tools: ToolRegistry;
  private readonly stageExecutor: StageExecutor;
  private readonly stageMap: Map<string, StageSpec>;
  private readonly exitIds: ReadonlySet<string>;
  private readonly policiesByTrigger: Map<string, PolicySpec[]>;

  constructor(opts: {
    manifest: WorkflowManifest;
    tools: ToolRegistry;
    stageExecutor: StageExecutor;
  }) {
    this.manifest = opts.manifest;
    this.tools = opts.tools;
    this.stageExecutor = opts.stageExecutor;

    // Validate manifest structure
    this.tools.requireCapabilities(this.manifest.capabilities);

    this.stageMap = new Map();
    for (const s of this.manifest.stages) {
      if (this.stageMap.has(s.id)) {
        throw new WorkflowValidationError(
          `Workflow '${this.manifest.workflowId}' has duplicate stage id '${s.id}'`,
        );
      }
      this.stageMap.set(s.id, s);
    }

    if (!this.stageMap.has(this.manifest.entryStageId)) {
      throw new WorkflowValidationError(
        `Workflow '${this.manifest.workflowId}': entry stage '${this.manifest.entryStageId}' not found`,
      );
    }
    for (const exitId of this.manifest.exitStageIds) {
      if (!this.stageMap.has(exitId)) {
        throw new WorkflowValidationError(
          `Workflow '${this.manifest.workflowId}': exit stage '${exitId}' not found`,
        );
      }
    }
    for (const stage of this.manifest.stages) {
      for (const t of stage.transitions) {
        if (!this.stageMap.has(t.to)) {
          throw new WorkflowValidationError(
            `Workflow '${this.manifest.workflowId}': stage '${stage.id}' has transition to unknown stage '${t.to}'`,
          );
        }
      }
    }

    this.exitIds = this.manifest.exitStageIds;
    this.policiesByTrigger = new Map();
    for (const p of this.manifest.policies) {
      let list = this.policiesByTrigger.get(p.trigger.capability);
      if (!list) {
        list = [];
        this.policiesByTrigger.set(p.trigger.capability, list);
      }
      list.push(p);
    }
  }

  private requireStage(stageId: string): StageSpec {
    const stage = this.stageMap.get(stageId);
    if (!stage) {
      throw new WorkflowValidationError(`Stage '${stageId}' not found in manifest`);
    }
    return stage;
  }

  private makeStageContext(
    stage: StageSpec,
    inputs: Record<string, unknown>,
    readable: Record<string, unknown>,
    options: RunOptions,
    emitter: WorkflowEventEmitter,
    recorder?: TraceRecorder | NoOpTraceRecorder | null,
  ): StageContext {
    return {
      workflowId: this.manifest.workflowId,
      stage,
      inputs,
      readableContext: readable,
      allowedCapabilities: stage.requires,
      options,
      callTool: (capability, args, toolName) =>
        this.enforceAndCall(stage, capability, args, inputs, options, emitter, toolName, { recorder }),
      eventEmitter: emitter,
      traceRecorder: recorder ?? null,
    };
  }

  /**
   * Policy enforcement + tool call.
   *
   * Mirrors `_enforce_and_call_with_policies`:
   * 1. Check capability is in stage requires (unless policy-required).
   * 2. Deny policies before handler (truthy → PolicyDeniedError).
   * 3. Before-chains run required capabilities first (user.confirm=false blocks).
   * 4. Emit tool_call_started → handler → tool_call_completed/failed.
   */
  async enforceAndCall(
    stage: StageSpec,
    capability: string,
    args: Record<string, unknown>,
    inputs: Record<string, unknown>,
    runOpts: RunOptions,
    emitter: WorkflowEventEmitter,
    toolName?: string,
    opts?: { allowBefore?: boolean; recorder?: TraceRecorder | NoOpTraceRecorder | null },
  ): Promise<unknown> {
    const allowBefore = opts?.allowBefore ?? true;

    // Check capability visibility (unless this is a policy-required call)
    if (allowBefore && !stage.requires.has(capability)) {
      throw new MissingCapabilityError(
        `capability '${capability}' is not available in stage '${stage.id}'`,
      );
    }

    return this.enforceAndCallWithPolicies(capability, args, inputs, stage, {
      allowBefore,
      runOpts,
      emitter,
      toolName,
      recorder: opts?.recorder,
    });
  }

  private async enforceAndCallWithPolicies(
    capability: string,
    args: Record<string, unknown>,
    inputs: Record<string, unknown>,
    stage: StageSpec,
    opts: {
      allowBefore: boolean;
      runOpts: RunOptions;
      emitter: WorkflowEventEmitter;
      toolName?: string;
      recorder?: TraceRecorder | NoOpTraceRecorder | null;
    },
  ): Promise<unknown> {
    const { allowBefore, runOpts, emitter, toolName } = opts;
    const rec = resolveRecorder(opts.recorder);
    const policies = this.policiesByTrigger.get(capability) ?? [];

    // --- Tool preflight (before policies render UI / build messages) ---
    // Resolved the same way as the tool-call section below so a tool's own
    // configured limits (e.g. jsSandboxMaxCodeBytes) govern the pre-policy
    // path, not just the runner execution path.
    const preflightTool = toolName
      ? this.tools.getByName(toolName)
      : this.tools.get(capability);
    preflightTool?.preflight?.(args);

    // --- Deny policies ---
    for (const policy of policies) {
      if (policy.kind === "deny" && policy.condition) {
        const boundArgs = bindTriggerArgs(policy.trigger, args, policy.id, capability);
        const tapedOutcome = (rec as unknown as { consumeTapedPolicy?: (id: unknown) => string | null }).consumeTapedPolicy?.(policy.id) ?? null;
        if (tapedOutcome !== null) {
          const denied = tapedOutcome === "denied";
          await emitter.emit("policy_checked", {
            stageId: stage.id,
            capability,
            metadata: { policyId: policy.id, policyKind: "deny", denied },
          });
          (rec as unknown as { recordPolicyEvaluation?: (...a: unknown[]) => void }).recordPolicyEvaluation?.(null, policy.id, boundArgs, denied ? "denied" : "allowed");
          if (denied) {
            await emitter.emit("policy_denied", {
              stageId: stage.id,
              capability,
              error: `Policy '${policy.id}' denied capability '${capability}'`,
              metadata: { policyId: policy.id },
            });
            throw new PolicyDeniedError(`Policy '${policy.id}' denied capability '${capability}'`);
          }
          continue;
        }
        const ctx: PolicyRefContext = { inputs, boundArgs, policyId: policy.id, capability };
        const resolve = (ref: Parameters<typeof resolvePolicyRef>[0]) => resolvePolicyRef(ref, ctx);
        const recurse = (e: Parameters<typeof evalExpr>[0]) => evalExpr(e, resolve, recurse);
        let denied: boolean;
        try {
          denied = Boolean(recurse(policy.condition));
        } catch (e) {
          if (e instanceof DataUnavailableError) {
            await emitter.emit("policy_checked", {
              stageId: stage.id,
              capability,
              metadata: { policyId: policy.id, policyKind: "deny", denied: true, error: String(e) },
            });
            (rec as unknown as { recordPolicyEvaluation?: (...a: unknown[]) => void }).recordPolicyEvaluation?.(null, policy.id, boundArgs, "denied");
            throw new PolicyEvaluationError(
              `Policy '${policy.id}': condition evaluation failed for capability '${capability}': ${e}`,
            );
          }
          throw e;
        }
        await emitter.emit("policy_checked", {
          stageId: stage.id,
          capability,
          metadata: { policyId: policy.id, policyKind: "deny", denied },
        });
        (rec as unknown as { recordPolicyEvaluation?: (...a: unknown[]) => void }).recordPolicyEvaluation?.(null, policy.id, boundArgs, denied ? "denied" : "allowed");
        if (denied) {
          await emitter.emit("policy_denied", {
            stageId: stage.id,
            capability,
            error: `Policy '${policy.id}' denied capability '${capability}'`,
            metadata: { policyId: policy.id },
          });
          throw new PolicyDeniedError(
            `Policy '${policy.id}' denied capability '${capability}'`,
          );
        }
      }
    }

    // --- Before policies ---
    for (const policy of policies) {
      if (policy.kind === "before" && allowBefore) {
        const boundArgs = bindTriggerArgs(policy.trigger, args, policy.id, capability);
        if (emitter.hasSink || emitter.hasObserver) {
          const requiredCaps = policy.requires.map((r) => r.capability);
          await emitter.emit("policy_checked", {
            stageId: stage.id,
            capability,
            metadata: { policyId: policy.id, policyKind: "before", requiredCapabilities: requiredCaps },
          });
        }
        for (const req of policy.requires) {
          const reqArgs = resolveRequiredArgs(req, inputs, boundArgs, policy.id, capability);
          // Special case: user.confirm without explicit args. Dynamic code
          // workflows are required to declare this policy form; show the
          // actual source before the opaque-origin sandbox is created.
          if (
            Object.keys(reqArgs).length === 0 &&
            req.capability === "user.confirm"
          ) {
            reqArgs.message = capability === "browser.js.sandbox"
              ? sandboxApprovalMessage(args)
              : `Allow policy-required call before ${capability}?`;
          }
          checkRequiredArgsPresent(req.capability, reqArgs, policy.id, capability);
          // Recursively enforce (deny policies still apply, but not nested before)
          const result = await this.enforceAndCall(
            stage,
            req.capability,
            reqArgs,
            inputs,
            runOpts,
            emitter,
            undefined,
            { allowBefore: false, recorder: rec },
          );
          if (req.capability === "user.confirm" && result === false) {
            await emitter.emit("policy_denied", {
              stageId: stage.id,
              capability,
              error: `user.confirm returned False for policy '${policy.id}'`,
              metadata: { policyId: policy.id },
            });
            (rec as unknown as { recordPolicyEvaluation?: (...a: unknown[]) => void }).recordPolicyEvaluation?.(null, policy.id, boundArgs, "denied");
            throw new PolicyDeniedError(
              `Policy '${policy.id}': user.confirm returned False, blocking capability '${capability}'`,
            );
          }
        }
        (rec as unknown as { recordPolicyEvaluation?: (...a: unknown[]) => void }).recordPolicyEvaluation?.(null, policy.id, boundArgs, "allowed");
      }
    }

    // --- Tool call ---
    const tool = toolName
      ? this.tools.getByName(toolName)
      : this.tools.get(capability);
    const resolvedName = tool?.name ?? capability;

    // Assign the trace tool-call id before the live event so the recorder
    // can attribute the observed event deterministically.
    const toolCallId = rec.beginToolCall(stage.id);

    await emitter.emit("tool_call_started", {
      stageId: stage.id,
      capability,
      toolName: resolvedName,
      args: { ...args },
    });

    const ctx: ToolContext = {
      workflowId: this.manifest.workflowId,
      stageId: stage.id,
      inputs,
      metadata: runOpts.metadata,
      signal: runOpts.signal,
    };

    try {
      const result = await this.tools.call(capability, args, ctx, toolName);
      (rec as unknown as { recordToolResult?: (...a: unknown[]) => void }).recordToolResult?.(toolCallId, result, args);
      await emitter.emit("tool_call_completed", {
        stageId: stage.id,
        capability,
        toolName: resolvedName,
        metadata: { resultPreview: safeResultPreview(result) },
      });
      return result;
    } catch (e) {
      rec.recordToolError(toolCallId, e);
      const errorMsg = e instanceof Error ? `${e.constructor.name}: ${e.message}` : String(e);
      await emitter.emit("tool_call_failed", {
        stageId: stage.id,
        capability,
        toolName: resolvedName,
        error: errorMsg,
      });
      throw e;
    }
  }

  // -----------------------------------------------------------------
  // Public execution
  // -----------------------------------------------------------------

  async run(
    inputs: Record<string, unknown>,
    opts?: {
      options?: Partial<RunOptions>;
      eventSink?: WorkflowEventSink | null;
      traceRecorder?: TraceRecorder | NoOpTraceRecorder | null;
    },
  ): Promise<WorkflowResult> {
    const options = resolveRunOptions(opts?.options);
    const stageOutputs: Record<string, Record<string, unknown>> = {};
    let currentId = this.manifest.entryStageId;
    let steps = 0;
    const runId = generateRunId();
    const rec = resolveRecorder(opts?.traceRecorder);
    rec.beginRun(this.manifest);
    (rec as unknown as { recordRunInputs?: (i: unknown) => void }).recordRunInputs?.(inputs);
    // Trace observer does not count as a live sink, so provider streaming
    // stays gated on a real caller consumer.
    const userSink = opts?.eventSink ?? null;
    const observer: import("./events.js").WorkflowEventObserver | null =
      opts?.traceRecorder instanceof TraceRecorder
        ? (event) => rec.observeWorkflowEvent(event)
        : null;
    const emitter = new WorkflowEventEmitter(runId, userSink, observer);

    await emitter.emit("run_started", {
      metadata: { workflowId: this.manifest.workflowId, entry: currentId },
    });

    // Set once the success path finalizes, so a finalization failure itself
    // never triggers a second terminal event/finalization below.
    let finalized = false;

    try {
      while (true) {
        if (steps >= options.maxSteps) {
          throw new MaxStepsExceededError(
            `Workflow '${this.manifest.workflowId}' exceeded maxSteps=${options.maxSteps}`,
          );
        }
        if (options.signal?.aborted) {
          throw new NemoIRRuntimeError("workflow run cancelled by abort signal");
        }

        const stage = this.requireStage(currentId);
        const readable = resolveReads(stage, inputs, stageOutputs);
        const ctx = this.makeStageContext(stage, inputs, readable, options, emitter, rec);
        const visitId = rec.beginStageVisit(stage.id);

        await emitter.emit("stage_started", { stageId: stage.id });

        // Dispatch: the stage executor handles both model and tool stages.
        // The composite executor in WorkflowAgent routes by stage.execution.kind.
        const rawOutput = await this.stageExecutor.execute(ctx);

        validateOutput(stage, rawOutput);
        const normalized = normalizeOptionalEmptyArrays(stage, rawOutput);
        // Store output, replacing any previous output from earlier iterations
        stageOutputs[stage.id] = normalized;
        steps++;

        await emitter.emit("stage_completed", {
          stageId: stage.id,
          output: { ...normalized },
        });

        if (this.exitIds.has(stage.id)) {
          const result: WorkflowResult = {
            output: rawOutput,
            state: {
              currentStageId: stage.id,
              stageOutputs: { ...stageOutputs },
              steps,
            },
          };
          await emitter.emit("run_completed", { result });
          finalized = true;
          await rec.finishRun("complete");
          return result;
        }

        const selected = selectTransition(stage, inputs, stageOutputs, rec, visitId);
        await emitter.emit("transition_selected", {
          stageId: stage.id,
          transitionTo: selected.to,
          metadata: { reason: selected.reason, priority: selected.priority },
        });
        currentId = selected.to;
      }
    } catch (error) {
      if (finalized) throw error;
      if (options.signal?.aborted) {
        // Cancellation: finalize as interrupted without a live failure
        // event, and never mask the original error.
        await rec.finishRun("interrupted").catch(() => {});
        throw error;
      }
      rec.recordRunError(error);
      const errorMsg = error instanceof Error ? error.message : String(error);
      await emitter.emit("run_failed", {
        error: errorMsg,
        metadata: { reason: error instanceof Error ? error.constructor.name : "Error" },
      });
      // A blocked finalization is loud; preserve the original as the cause.
      try {
        await rec.finishRun("failed");
      } catch (finishError) {
        (finishError as Error).cause = error;
        throw finishError;
      }
      throw error;
    }
  }

  /**
   * Async-iterable stream of events.
   *
   * Events are yielded live (not post-hoc). If the consumer breaks out
   * early, the run is cancelled cooperatively.
   */
  async *stream(
    inputs: Record<string, unknown>,
    opts?: { options?: Partial<RunOptions>; traceRecorder?: TraceRecorder | NoOpTraceRecorder | null },
  ): AsyncIterable<WorkflowEvent> {
    const callerOptions = resolveRunOptions(opts?.options);
    // Compose the caller's signal with an internal controller so that an
    // early consumer break can also cancel the background run.
    const controller = new AbortController();
    const callerSignal = callerOptions.signal;
    if (callerSignal) {
      if (callerSignal.aborted) {
        controller.abort();
      } else {
        callerSignal.addEventListener("abort", () => controller.abort(), { once: true });
      }
    }
    const options: RunOptions = { ...callerOptions, signal: controller.signal };

    const queue: WorkflowEvent[] = [];
    let resolveWait: (() => void) | null = null;
    let done = false;
    let runError: unknown = null;
    let completedNormally = false;

    const sink: WorkflowEventSink = async (event) => {
      queue.push(event);
      if (resolveWait) {
        const r = resolveWait;
        resolveWait = null;
        r();
      }
    };

    // Run in the background
    const runPromise = this.run(inputs, { options, eventSink: sink, traceRecorder: opts?.traceRecorder ?? null })
      .catch((e) => {
        runError = e;
      })
      .finally(() => {
        done = true;
        if (resolveWait) {
          const r = resolveWait;
          resolveWait = null;
          r();
        }
      });

    // Yield events as they arrive
    try {
      while (!done || queue.length > 0) {
        if (queue.length === 0) {
          await new Promise<void>((resolve) => {
            resolveWait = resolve;
          });
        }
        while (queue.length > 0) {
          yield queue.shift()!;
        }
      }
      await runPromise;
      if (runError) throw runError;
      completedNormally = true;
    } finally {
      // If the consumer broke out early, abort the run so the background
      // model generation does not keep running unobserved.
      if (!completedNormally && !controller.signal.aborted) {
        controller.abort();
      }
      // Ensure the background promise is settled
      await runPromise.catch(() => {});
    }
  }
}
