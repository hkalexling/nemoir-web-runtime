/**
 * NemoTrace taped replay (Phase 4, standalone core) — TypeScript port of
 * python/nemoir-runtime/src/nemoir_runtime/replay.py
 *
 * Re-executes a recorded run's state-machine path with no live effects.
 */

import { parseJsonStrict } from "./canonical.js";
import { ToolInvocationError } from "./errors.js";
import type { WorkflowEvent, WorkflowEventSink } from "./events.js";
import type { WorkflowManifest, StageSpec, PolicySpec, TransitionSpec, ReadSpec, RequiredCapabilitySpec, ExprSpec, GuardSpec, RefSpec } from "./manifest.js";
import { ModelStageExecutor } from "./models.js";
import { WorkflowRuntime } from "./runtime.js";
import type { RunOptions } from "./runtime-types.js";
import { ToolRegistry } from "./tools.js";
import type { Tool, ToolContext } from "./tools.js";
import { NoOpTraceRecorder, policyRefsFor, unlockArchive, readArchiveEntries } from "./trace.js";
import type { VerificationReport } from "./trace.js";

export class TapedReplayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TapedReplayError";
  }
}

export interface ReplayReport {
  readonly matched: boolean;
  readonly divergences: readonly string[];
  readonly verification: VerificationReport;
  readonly steps: number;
  readonly replayedStatus: string;
}

// ---------------------------------------------------------------------------
// Manifest reconstruction helpers
// ---------------------------------------------------------------------------

function reqDict(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TapedReplayError(`${what} must be an object`);
  return value as Record<string, unknown>;
}
function reqList(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new TapedReplayError(`${what} must be an array`);
  return value;
}

function refFromDict(data: unknown): RefSpec | null {
  if (data === null || data === undefined) return null;
  const m = reqDict(data, "manifest RefSpec");
  const kind = m["kind"] as string;
  if (kind !== "input" && kind !== "node_output" && kind !== "bound") throw new TapedReplayError(`manifest RefSpec has invalid kind ${JSON.stringify(kind)}`);
  if (kind === "input") return { kind: "input", name: m["name"] as string };
  if (kind === "node_output") return { kind: "node_output", node: m["node"] as string, field: m["field"] as string };
  return { kind: "bound", name: m["name"] as string };
}

function exprFromDict(data: unknown): ExprSpec | null {
  if (data === null || data === undefined) return null;
  const m = reqDict(data, "manifest ExprSpec");
  const kind = m["kind"] as string;
  if (!["not", "method_call", "ref", "literal", "and", "or", "compare", "binop"].includes(kind)) throw new TapedReplayError(`manifest ExprSpec has invalid kind ${JSON.stringify(kind)}`);
  const rawArgs = reqList(m["args"] ?? [], "manifest ExprSpec args");
  const rawExprs = reqList(m["exprs"] ?? [], "manifest ExprSpec exprs");
  return {
    kind: kind as ExprSpec["kind"],
    // @ts-ignore dynamic
    expr: exprFromDict(m["expr"]),
    receiver: exprFromDict(m["receiver"]),
    method: m["method"] as string | undefined,
    args: rawArgs.map((a) => exprFromDict(a)).filter((v): v is ExprSpec => v !== null),
    exprs: rawExprs.map((e) => exprFromDict(e)).filter((v): v is ExprSpec => v !== null),
    ref: refFromDict(m["ref"]),
    type: m["type"] as string | undefined,
    value: m["value"],
    op: m["op"] as string | undefined,
    left: exprFromDict(m["left"]),
    right: exprFromDict(m["right"]),
  } as unknown as ExprSpec;
}

function guardFromDict(data: unknown): GuardSpec {
  const m = reqDict(data, "manifest GuardSpec");
  const kind = m["kind"] as string;
  if (!["always", "has_value", "missing", "eq", "if"].includes(kind)) throw new TapedReplayError(`manifest GuardSpec has invalid kind ${JSON.stringify(kind)}`);
  if (kind === "always") return { kind: "always" };
  if (kind === "has_value") return { kind: "has_value", ref: refFromDict(m["ref"])! };
  if (kind === "missing") return { kind: "missing", ref: refFromDict(m["ref"])! };
  if (kind === "eq") return { kind: "eq", left: exprFromDict(m["left"])!, right: exprFromDict(m["right"])! };
  return { kind: "if", cond: exprFromDict(m["cond"])! };
}

function readFromDict(data: unknown): ReadSpec {
  const m = reqDict(data, "vault manifest read");
  const ref = refFromDict(m["ref"]);
  if (ref === null) throw new TapedReplayError("vault manifest read requires a ref");
  return { ref, optional: Boolean(m["optional"]) };
}

export function manifestFromDict(data: unknown): WorkflowManifest {
  const root = reqDict(data, "vault manifest snapshot");
  const manifestData = (root["manifest"] as unknown) ?? root;
  const mm = reqDict(manifestData, "vault manifest snapshot");
  const rawStages = reqList(mm["stages"], "vault manifest stages");
  const rawPolicies = reqList(mm["policies"] ?? [], "vault manifest policies");
  const rawInputs = reqList(mm["inputs"] ?? [], "vault manifest inputs");
  const rawExits = reqList(mm["exit_stage_ids"] ?? [], "vault manifest exits");
  const rawCapabilities = reqList(mm["capabilities"] ?? [], "vault manifest capabilities");

  const stages: StageSpec[] = [];
  for (const rawStage of rawStages) {
    const stage = reqDict(rawStage, "vault manifest stage");
    const executionMap = reqDict(stage["execution"] ?? {}, "vault manifest execution");
    const execArgsMap = reqDict(executionMap["args"] ?? {}, "vault manifest execution args");
    const execArgs = new Map<string, ExprSpec>();
    for (const [k, v] of Object.entries(execArgsMap)) {
      const parsed = exprFromDict(v);
      if (parsed) execArgs.set(String(k), parsed);
    }
    const rawWrites = reqList(stage["writes"] ?? [], "vault manifest writes");
    const rawTransitions = reqList(stage["transitions"] ?? [], "vault manifest transitions");
    const rawReads = reqList(stage["reads"] ?? [], "vault manifest reads");
    const rawRequires = reqList(stage["requires"] ?? [], "vault manifest requires");
    const transitions: TransitionSpec[] = [];
    for (const rawTransition of rawTransitions) {
      const tm = reqDict(rawTransition, "vault manifest transition");
      transitions.push({
        to: String(tm["to"]),
        priority: Number(tm["priority"] ?? 0) || 0,
        reason: String(tm["reason"] ?? "other"),
        guard: guardFromDict(tm["guard"]),
      });
    }
    const executionKind = executionMap["kind"] as string ?? "model";
    stages.push({
      id: String(stage["id"]),
      prompt: String(stage["prompt"] ?? ""),
      reads: rawReads.map((r) => readFromDict(r)),
      writes: rawWrites.map((w) => {
        const wm = reqDict(w, "vault manifest write");
        return { name: String(wm["name"]), type: String(wm["type"]), optional: Boolean(wm["optional"]) };
      }),
      requires: new Set((rawRequires as string[]).map((c) => String(c))),
      transitions,
      execution: {
        kind: executionKind === "tool" ? "tool" : "model",
        capability: executionMap["capability"] as string | undefined ?? undefined,
        args: execArgs,
      },
    });
  }

  const policies: PolicySpec[] = [];
  for (const rawPolicy of rawPolicies) {
    const pm = reqDict(rawPolicy, "vault manifest policy");
    const triggerMap = reqDict(pm["trigger"], "vault manifest trigger");
    const bindMap = reqDict(triggerMap["bind"] ?? {}, "vault manifest bind");
    const rawReqList = reqList(pm["requires"] ?? [], "vault manifest requires");
    const requires: RequiredCapabilitySpec[] = [];
    for (const rawReq of rawReqList) {
      const rm = reqDict(rawReq, "vault manifest requirement");
      const reqArgsMap = reqDict(rm["args"] ?? {}, "vault manifest req args");
      const reqArgs = new Map<string, RefSpec>();
      for (const [k, v] of Object.entries(reqArgsMap)) {
        const parsed = refFromDict(v);
        if (parsed) reqArgs.set(String(k), parsed);
      }
      requires.push({ capability: String(rm["capability"]), args: reqArgs });
    }
    const pKind = pm["kind"] as string ?? "deny";
    policies.push({
      id: String(pm["id"]),
      kind: pKind === "before" ? "before" : "deny",
      trigger: {
        capability: String(triggerMap["capability"]),
        bind: new Map(Object.entries(bindMap).map(([k, v]) => [String(k), String(v as string)])),
      },
      requires,
      condition: exprFromDict(pm["condition"]),
    });
  }

  const workflowId = mm["workflow_id"] as string;
  const entryStageId = mm["entry_stage_id"] as string;
  if (typeof workflowId !== "string" || typeof entryStageId !== "string") throw new TapedReplayError("vault manifest snapshot has invalid workflow/entry ids");
  return {
    workflowId,
    entryStageId,
    exitStageIds: new Set((rawExits as string[]).map((e) => String(e))),
    inputs: (rawInputs as unknown[]).map((i) => {
      const m = reqDict(i, "vault manifest input");
      // python snapshot uses {name, type}
      const name = (m["name"] as string) ?? (m["id"] as string);
      return { id: String(name), type: String(m["type"]) };
    }),
    capabilities: new Set((rawCapabilities as string[]).map((c) => String(c))),
    policies,
    stages,
  };
}

// ---------------------------------------------------------------------------
// Policy tape helper (mirror python _policy_tape_for_replay)
// ---------------------------------------------------------------------------

function policyTapeForReplay(records: Record<string, unknown>[], manifest: WorkflowManifest): Map<string, string[]> {
  const refs = policyRefsFor(manifest.policies as unknown as { id: string }[]);
  const idByRef = new Map<string, string>();
  for (const [pid, ref] of refs.entries()) idByRef.set(ref, pid);
  const tape = new Map<string, string[]>();
  for (const record of records) {
    if (record["record_type"] !== "policy_evaluation") continue;
    const payload = record["payload"] as Record<string, unknown> | undefined;
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) continue;
    const ref = payload["policy_ref"] as string | undefined;
    const outcome = payload["outcome"] as string | undefined;
    const policyId = typeof ref === "string" ? idByRef.get(ref) : undefined;
    if (policyId === undefined || (outcome !== "allowed" && outcome !== "denied")) continue;
    let arr = tape.get(policyId);
    if (!arr) { arr = []; tape.set(policyId, arr); }
    arr.push(outcome);
  }
  return tape;
}

// ---------------------------------------------------------------------------
// Taped fixtures
// ---------------------------------------------------------------------------

const WRITE_TYPE_MAP: Record<string, string> = {
  string: "string",
  bool: "boolean",
  number: "number",
  path: "string",
  "string[]": "string[]",
  json: "json",
};

function isRedactionMarker(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  return "$redacted" in (value as Record<string, unknown>) && typeof (value as Record<string, unknown>)["$redacted"] === "object";
}

function fixturePlaceholder(marker: Record<string, unknown>): unknown {
  const inner = (marker["$redacted"] as Record<string, unknown>) ?? {};
  const valueType = inner["value_type"] as string | undefined;
  const length = inner["length"] as number | undefined;
  const count = typeof length === "number" && length >= 0 ? length : 0;
  if (valueType === "string") return "?".repeat(count);
  if (valueType === "number") return 0;
  if (valueType === "boolean") return false;
  if (valueType === "array") return [];
  if (valueType === "object") return {};
  return null;
}

function unmarkFixture(value: unknown): unknown {
  if (isRedactionMarker(value)) return fixturePlaceholder(value as Record<string, unknown>);
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = unmarkFixture(v);
    return out;
  }
  if (Array.isArray(value)) return (value as unknown[]).map((v) => unmarkFixture(v));
  return value;
}

function markerAwareEqual(replayed: unknown, recorded: unknown): boolean {
  if (isRedactionMarker(recorded)) return true;
  if (recorded !== null && typeof recorded === "object" && !Array.isArray(recorded)) {
    if (replayed === null || typeof replayed !== "object" || Array.isArray(replayed)) return false;
    const rm = recorded as Record<string, unknown>;
    const pm = replayed as Record<string, unknown>;
    for (const [k, v] of Object.entries(rm)) {
      if (!(k in pm) || !markerAwareEqual(pm[k], v)) return false;
    }
    return true;
  }
  if (Array.isArray(recorded)) {
    if (!Array.isArray(replayed)) return false;
    if ((replayed as unknown[]).length !== (recorded as unknown[]).length) return false;
    return (recorded as unknown[]).every((v, i) => markerAwareEqual((replayed as unknown[])[i], v));
  }
  return replayed === recorded;
}

// Export helpers for tests (mirror python internal exposure)
export const _testHelpers = { fixturePlaceholder, unmarkFixture, markerAwareEqual, isRedactionMarker };

function inferStubType(value: unknown): string {
  if (typeof value === "boolean") return "bool";
  if (typeof value === "number") return "number";
  if (typeof value === "string") return "string";
  if (Array.isArray(value) && (value as unknown[]).every((item) => typeof item === "string")) return "string[]";
  return "string";
}

function recordedArgShapes(records: Record<string, unknown>[]): Map<string, string> {
  const shapes = new Map<string, string>();
  for (const record of records) {
    const payload = record["payload"] as Record<string, unknown> | undefined;
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) continue;
    const argSets: Record<string, unknown>[] = [];
    if (record["record_type"] === "tool_result") {
      const args = payload["args"] as Record<string, unknown> | undefined;
      if (args !== null && typeof args === "object" && !Array.isArray(args)) argSets.push(args);
    } else if (record["record_type"] === "model_response") {
      const calls = payload["tool_calls"] as unknown[] | undefined;
      if (Array.isArray(calls)) {
        for (const call of calls) {
          if (call !== null && typeof call === "object" && !Array.isArray(call) && typeof (call as Record<string, unknown>)["arguments"] === "object" && (call as Record<string, unknown>)["arguments"] !== null && !Array.isArray((call as Record<string, unknown>)["arguments"])) {
            argSets.push((call as Record<string, unknown>)["arguments"] as Record<string, unknown>);
          }
        }
      }
    }
    for (const args of argSets) {
      for (const [key, value] of Object.entries(args)) {
        if (typeof key === "string" && !shapes.has(key)) shapes.set(key, inferStubType(value));
      }
    }
  }
  return shapes;
}

export class TapedModelAdapter {
  private readonly queues: Map<string, Record<string, unknown>[]>;
  calls = 0;
  constructor(responsesByStage: Map<string, Record<string, unknown>[]> | Record<string, Record<string, unknown>[]>) {
    this.queues = new Map();
    if (responsesByStage instanceof Map) {
      for (const [k, v] of responsesByStage.entries()) this.queues.set(k, [...v]);
    } else {
      for (const [k, v] of Object.entries(responsesByStage as Record<string, Record<string, unknown>[]>)) this.queues.set(k, [...v]);
    }
  }
  async complete(request: { stageId: string } & Record<string, unknown>): Promise<import("./model-contract.js").ModelResponse> {
    this.calls += 1;
    const q = this.queues.get(request.stageId);
    if (!q || q.length === 0) throw new TapedReplayError(`taped replay has no model fixture for stage '${request.stageId}' (call ${this.calls})`);
    const fixture = q.shift()!;
    const toolCallsRaw = unmarkFixture(fixture["tool_calls"]);
    const callsList = Array.isArray(toolCallsRaw) ? toolCallsRaw : [];
    const toolCalls = callsList.filter((c) => c !== null && typeof c === "object").map((c) => {
      const m = c as Record<string, unknown>;
      const argsRaw = m["arguments"] as Record<string, unknown> | undefined;
      const args = argsRaw !== null && typeof argsRaw === "object" && !Array.isArray(argsRaw) ? (unmarkFixture(argsRaw) as Record<string, unknown>) : {};
      return { id: String(m["id"] ?? ""), name: String(m["name"] ?? ""), arguments: args };
    });
    const reasoningRaw = fixture["reasoning"];
    const reasoning = isRedactionMarker(reasoningRaw) ? null : (reasoningRaw as string | null);
    const contentRaw = fixture["content"];
    const content = isRedactionMarker(contentRaw) ? (unmarkFixture(contentRaw) as string | null) : (contentRaw as string | null);
    // Also unmark top-level content if it was an object marker? In practice content is string|null.
    const finalContent = typeof content === "string" || content === null ? content : (unmarkFixture(content) as string | null);
    return { content: finalContent as string | null, toolCalls, reasoning };
  }
}

export class TapedToolRegistry extends ToolRegistry {
  private fixtures: Record<string, unknown>[];
  calls: Record<string, unknown>[] = [];
  private readonly toolsByRecordedName = new Map<string, Tool>();
  constructor(fixtures: Record<string, unknown>[], stubSchemas?: Map<string, Record<string, unknown>> | Record<string, Record<string, unknown>>) {
    const list = [...fixtures];
    const schemas = new Map<string, Record<string, unknown>>();
    if (stubSchemas instanceof Map) {
      for (const [k, v] of stubSchemas.entries()) schemas.set(k, v as Record<string, unknown>);
    } else if (stubSchemas) {
      for (const [k, v] of Object.entries(stubSchemas as Record<string, Record<string, unknown>>)) schemas.set(k, v);
    }
    const capabilities = new Set<string>();
    for (const f of list) {
      const cap = (f as Record<string, unknown>)["capability"] as string;
      if (typeof cap === "string") capabilities.add(cap);
    }
    for (const cap of schemas.keys()) capabilities.add(cap);
    const stubs: Tool[] = [];
    for (const cap of capabilities) {
      const schema = schemas.get(cap) ?? { inputs: {}, outputs: {} };
      const inputs = (schema["inputs"] as Record<string, unknown>) ?? {};
      const outputs = (schema["outputs"] as Record<string, unknown>) ?? {};
      const inputSchema: Record<string, import("./tools.js").ToolParamType> = {};
      for (const [n, kind] of Object.entries(inputs)) {
        const t = WRITE_TYPE_MAP[String(kind)] ?? "json";
        inputSchema[n] = t as import("./tools.js").ToolParamType;
      }
      stubs.push({
        name: `taped-${cap}`,
        capability: cap,
        description: "Taped replay stub (no live effects).",
        inputSchema,
        handler: async () => { throw new TapedReplayError("taped tools serve fixtures through TapedToolRegistry.call"); },
        outputSchema: Object.keys(outputs).length>0 ? {} as unknown as Record<string, string> : null,
      });
    }
    super(stubs.length>0 ? stubs : [{ name: "taped-dummy", capability: "fs.read", description: "dummy", inputSchema: { path: "string" }, handler: async () => ({}) }]);
    if (stubs.length===0) {
      (this as unknown as { byCapability: Map<string, Tool[]> }).byCapability.clear();
      (this as unknown as { byName: Map<string, Tool> }).byName.clear();
    }
    this.fixtures = list;
    // Build recorded-name -> stub map (first-seen wins)
    const byCapability = new Map<string, Tool>();
    for (const stub of stubs) byCapability.set(stub.capability, stub);
    for (const fixture of this.fixtures) {
      const toolName = (fixture as Record<string, unknown>)["tool_name"] as string | undefined;
      const capability = (fixture as Record<string, unknown>)["capability"] as string | undefined;
      if (typeof toolName !== "string") continue;
      if (this.toolsByRecordedName.has(toolName)) continue;
      const stub = typeof capability === "string" ? byCapability.get(capability) : undefined;
      if (stub) this.toolsByRecordedName.set(toolName, stub);
    }
  }

  override getByName(name: string): Tool | undefined {
    const stub = this.toolsByRecordedName.get(name);
    if (stub !== undefined) return stub;
    return super.getByName(name);
  }

  // Taped stubs are per-recorded-capability synthetic tools, not catalog
  // tools; skip catalog validation (mirrors Python `_validate_tools`).
  protected override _validateTools(_tools: readonly Tool[]): void { /* no-op */ }

  override async call(capability: string, args: Record<string, unknown>, ctx: ToolContext, toolName?: string): Promise<unknown> {
    if (this.fixtures.length === 0) throw new TapedReplayError(`taped replay has no tool fixture for capability '${capability}' at stage '${ctx.stageId}'`);
    const fixture = this.fixtures.shift()! as Record<string, unknown>;
    this.calls.push({ capability, toolName, args: { ...args }, fixture_capability: fixture["capability"], fixture_tool_name: fixture["tool_name"] });
    const payload = (fixture["payload"] as Record<string, unknown>) ?? fixture as unknown as Record<string, unknown>;
    if (payload !== null && typeof payload === "object" && "error" in payload) {
      const detail = (payload as Record<string, unknown>)["error"] as Record<string, unknown>;
      const code = (detail as Record<string, unknown>)?.["code"] as string ?? "tool_failed";
      throw new ToolInvocationError(`taped replay reproduces recorded tool failure (${code})`);
    }
    const result = (payload as Record<string, unknown>)["result"];
    if (isRedactionMarker(result)) throw new TapedReplayError(`taped replay cannot serve a redacted fixture for capability '${capability}'`);
    return unmarkFixture(result);
  }
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

const COMPARE_KINDS = new Set([
  "run_started",
  "stage_started",
  "model_completed",
  "model_retry",
  "tool_call_started",
  "tool_call_completed",
  "tool_call_failed",
  "policy_checked",
  "policy_denied",
  "transition_selected",
  "stage_completed",
  "run_completed",
  "run_failed",
]);

function liveKey(event: WorkflowEvent): unknown[] {
  const kind = event.kind;
  if (kind === "run_started") return [kind];
  if (kind === "run_completed" || kind === "run_failed") return [kind];
  const base: unknown[] = [kind, event.stageId];
  if (kind === "transition_selected") return [...base, event.transitionTo];
  if (kind === "tool_call_started" || kind === "tool_call_completed" || kind === "tool_call_failed") return [...base, event.capability];
  if (kind === "policy_checked") {
    const meta = event.metadata ?? {};
    // @ts-ignore
    return [...base, event.capability, (meta as Record<string, unknown>)["policy_kind"] ?? (meta as Record<string, unknown>)["policyKind"], (meta as Record<string, unknown>)["denied"]];
  }
  if (kind === "policy_denied") return [...base, event.capability];
  return base;
}

function ledgerKey(record: Record<string, unknown>): unknown[] {
  const kind = record["kind"] as string;
  if (kind === "run_started") return [kind];
  if (kind === "run_completed" || kind === "run_failed") return [kind];
  const base: unknown[] = [kind, record["stage_id"]];
  if (kind === "transition_selected") return [...base, record["transition_to"]];
  if (kind === "tool_call_started" || kind === "tool_call_completed" || kind === "tool_call_failed") return [...base, record["capability"]];
  if (kind === "policy_checked") {
    const meta = record["metadata"] as Record<string, unknown> | undefined;
    return [...base, record["capability"], meta?.["policy_kind"], meta?.["denied"]];
  }
  if (kind === "policy_denied") return [...base, record["capability"]];
  return base;
}



// ---------------------------------------------------------------------------
// Replay driver
// ---------------------------------------------------------------------------

export async function replayTrace(archive: Uint8Array, passphrase: string | Uint8Array, opts: { options?: RunOptions; eventSink?: WorkflowEventSink } = {}): Promise<ReplayReport> {
  const { records, report: unlockReport } = await unlockArchive(archive, passphrase as string | Uint8Array);
  if (!unlockReport.ok || unlockReport.replayability !== "taped-replay") {
    return { matched: false, divergences: unlockReport.errors.length>0 ? [...unlockReport.errors] : ["archive verification failed"], verification: unlockReport, steps: 0, replayedStatus: "unknown" };
  }
  const manifestRecord = records.find((r) => r["record_type"] === "full_workflow_ir");
  if (!manifestRecord) {
    return { matched: false, divergences: ["vault has no full_workflow_ir manifest snapshot"], verification: unlockReport, steps: 0, replayedStatus: "unknown" };
  }
  let manifest: WorkflowManifest;
  try {
    manifest = manifestFromDict(manifestRecord["payload"]);
  } catch (e) {
    return { matched: false, divergences: [`vault manifest snapshot unusable: ${String(e)}`], verification: unlockReport, steps: 0, replayedStatus: "unknown" };
  }
  let manifestStatus = "complete";
  try {
    const entries = readArchiveEntries(archive);
    const recordedManifest = parseJsonStrict(new TextDecoder().decode(entries["manifest.json"])) as Record<string, unknown>;
    if (recordedManifest !== null && typeof recordedManifest === "object" && !Array.isArray(recordedManifest)) {
      manifestStatus = String((recordedManifest as Record<string, unknown>)["status"] ?? "complete");
    }
  } catch (e) {
    return { matched: false, divergences: [`cannot read recorded terminal status: ${String(e)}`], verification: unlockReport, steps: 0, replayedStatus: "unknown" };
  }
  if (manifestStatus === "interrupted") {
    return { matched: false, divergences: ["interrupted traces are evidence, not replayable runs"], verification: unlockReport, steps: 0, replayedStatus: "unknown" };
  }
  const runInputsRecord = records.find((r) => r["record_type"] === "run_inputs");
  if (!runInputsRecord) {
    return { matched: false, divergences: ["vault has no run_inputs fixture"], verification: unlockReport, steps: 0, replayedStatus: "unknown" };
  }
  const replayInputs = runInputsRecord["payload"] as Record<string, unknown>;
  if (replayInputs === null || typeof replayInputs !== "object" || Array.isArray(replayInputs)) {
    return { matched: false, divergences: ["vault run_inputs payload must be an object"], verification: unlockReport, steps: 0, replayedStatus: "unknown" };
  }
  // Map visit -> stage
  const visitStage = new Map<string, string>();
  for (const rec of records) {
    const payload = rec["payload"] as Record<string, unknown> | undefined;
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) continue;
    const sid = (payload as Record<string, unknown>)["stage_id"] as string;
    if (typeof sid !== "string") continue;
    const visit = rec["stage_visit_id"] as string;
    if (typeof visit === "string" && !visitStage.has(visit)) visitStage.set(visit, sid);
  }
  const modelByStage = new Map<string, Record<string, unknown>[]>();
  const toolFixtures: Record<string, unknown>[] = [];
  for (const rec of records) {
    const rtype = rec["record_type"] as string;
    const payload = rec["payload"] as Record<string, unknown>;
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) continue;
    if (rtype === "model_response") {
      const visit = rec["stage_visit_id"] as string;
      const sid = visitStage.get(visit) ?? "";
      let arr = modelByStage.get(sid);
      if (!arr) { arr = []; modelByStage.set(sid, arr); }
      arr.push(payload);
    } else if (rtype === "tool_result") {
      toolFixtures.push({ capability: (payload as Record<string, unknown>)["capability"], tool_name: (payload as Record<string, unknown>)["tool_name"], payload, tool_call_id: rec["tool_call_id"] });
    }
  }
  const stubSchemas = new Map<string, Record<string, unknown>>();
  for (const cap of manifest.capabilities) stubSchemas.set(cap, { inputs: {}, outputs: {} });
  for (const stage of manifest.stages) {
    for (const cap of stage.requires) {
      let schema = stubSchemas.get(cap);
      if (!schema) { schema = { inputs: {}, outputs: {} }; stubSchemas.set(cap, schema); }
      if (stage.execution.kind === "tool" && stage.execution.capability === cap) {
        const inputs = (schema["inputs"] as Record<string, unknown>);
        for (const argName of stage.execution.args?.keys() ?? []) inputs[argName] = inputs[argName] ?? "string";
      }
      const outputs = (schema["outputs"] as Record<string, unknown>);
      for (const w of stage.writes) outputs[w.name] = outputs[w.name] ?? w.type;
    }
  }
  // Evidence-based input names: model-requested tool calls normalize against these stub schemas
  const recordedShapes = recordedArgShapes(records);
  for (const [argName, argKind] of recordedShapes.entries()) {
    for (const schema of stubSchemas.values()) {
      const inputs = schema["inputs"] as Record<string, unknown>;
      if (!(argName in inputs)) inputs[argName] = argKind;
    }
  }
  const tapedTools = new TapedToolRegistry(toolFixtures, stubSchemas);
  const tapedModel = new TapedModelAdapter(modelByStage);
  // Taped deny-policy outcomes: runtime reproduces recorded allow/deny instead of re-evaluating.
  const tapeRecorder = new NoOpTraceRecorder();
  (tapeRecorder as unknown as { policyTape: Map<string, string[]> }).policyTape = policyTapeForReplay(records, manifest);
  const modelExec = new ModelStageExecutor({ model: tapedModel as unknown as import("./model-contract.js").ModelAdapter, tools: tapedTools });
  const composite = {
    async execute(ctx: any) {
      if (ctx.stage.execution.kind === "tool") {
        const cap = ctx.stage.execution.capability as string;
        const args: Record<string, unknown> = {};
        for (const [name, ex] of (ctx.stage.execution.args as Map<string, any>) ?? new Map()) {
          if (ex.kind === "literal") args[name] = ex.value;
          else if (ex.kind === "ref" && ex.ref?.kind === "input") args[name] = (ctx.inputs as Record<string, unknown>)[ex.ref.name];
          else args[name] = ex.value;
        }
        const result = await ctx.callTool(cap, args) as Record<string, unknown>;
        const out: Record<string, unknown> = {};
        for (const w of ctx.stage.writes as any[]) if (w.name in result) out[w.name] = (result as Record<string, unknown>)[w.name];
        return out;
      }
      return modelExec.execute(ctx);
    },
  };
  const runtime = new WorkflowRuntime({ manifest, tools: tapedTools, stageExecutor: composite as any });
  const events: WorkflowEvent[] = [];
  const collector: WorkflowEventSink = async (e) => { events.push(e); if (opts.eventSink) await opts.eventSink(e); };
  let replayedStatus = "complete";
  let replayError: string | null = null;
  try {
    await runtime.run(replayInputs as Record<string, unknown>, { options: opts.options, eventSink: collector, traceRecorder: tapeRecorder });
  } catch (e) {
    if (e instanceof TapedReplayError) { replayedStatus = "failed"; replayError = `taped fixture error: ${String(e.message)}`; }
    else { replayedStatus = "failed"; replayError = `replayed run raised ${(e as Error).constructor.name}`; }
  }
  const divergences = await comparePaths(archive, events, records);
  if (manifestStatus === "failed" && replayedStatus !== "failed") divergences.push("recorded run failed but replay completed");
  else if (manifestStatus === "complete" && replayedStatus !== "complete") divergences.push(replayError ?? "recorded run completed but replay did not finish");
  const steps = events.filter((e) => e.kind === "stage_completed").length;
  return { matched: divergences.length===0, divergences, verification: unlockReport, steps, replayedStatus };
}

async function comparePaths(archive: Uint8Array, replayed: WorkflowEvent[], records: Record<string, unknown>[]): Promise<string[]> {
  const divergences: string[] = [];
  let entries: Record<string, Uint8Array>;
  try { entries = readArchiveEntries(archive); } catch (e) { return [`cannot re-read archive for comparison: ${String(e)}`]; }
  const ledger: Record<string, unknown>[] = [];
  const lines = new TextDecoder().decode(entries["public/events.ndjson"]).split("\n");
  for (const line of lines) {
    if (line.trim()==="") continue;
    const ev = parseJsonStrict(line) as Record<string, unknown>;
    if (COMPARE_KINDS.has(ev["kind"] as string)) ledger.push(ev);
  }
  const replayedKeys = replayed.filter((e) => COMPARE_KINDS.has(e.kind)).map((e) => liveKey(e));
  const ledgerKeys = ledger.map((e) => ledgerKey(e));
  if (replayedKeys.length !== ledgerKeys.length) divergences.push(`path length differs: replayed ${replayedKeys.length} milestone events, ledger has ${ledgerKeys.length}`);
  for (let i=0; i<Math.min(replayedKeys.length, ledgerKeys.length); i++) {
    const got = replayedKeys[i];
    const want = ledgerKeys[i];
    if (JSON.stringify(got) !== JSON.stringify(want)) { divergences.push(`divergence at milestone ${i}: replayed ${JSON.stringify(got)} != recorded ${JSON.stringify(want)}`); break; }
  }
  const snapshots = new Map<string, unknown>();
  for (const rec of records) if (rec["record_type"] === "stage_snapshot") snapshots.set(rec["stage_visit_id"] as string, rec["payload"]);
  const visitToOutput = new Map<string, unknown>();
  let counter = 0;
  let currentVisit = "";
  for (const ev of replayed) {
    if (ev.kind === "stage_started") { counter+=1; currentVisit = `s-${counter}`; }
    if (ev.kind === "stage_completed") visitToOutput.set(currentVisit, ev.output ?? {});
  }
  for (const [visit, snapshot] of snapshots.entries()) {
    const m = snapshot as Record<string, unknown>;
    const expected = (m["output"] as unknown) ?? {};
    const actual = visitToOutput.get(visit);
    if (actual === undefined) divergences.push(`replay never reached recorded visit ${visit}`);
    else if (!markerAwareEqual(actual, expected)) divergences.push(`stage output differs at visit ${visit}`);
  }
  return divergences;
}
