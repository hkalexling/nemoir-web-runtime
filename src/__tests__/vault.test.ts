/**
 * Vault parity tests — mirrors python/nemoir-runtime/tests/test_vault.py
 * Drives recorder through vault-fake-run.json ops with fixed clock+trace id+passphrase,
 * asserts byte-identical public/events.ndjson, workflow.graph.json AND decrypted vault plaintext.
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { canonicalStringify } from "../canonical.js";
import {
  TraceRecorder,
  TraceError,
  readArchiveEntries,
  verifyArchive,
  unlockArchive,
} from "../trace.js";
import type { WorkflowManifest } from "../manifest.js";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..", "..", "..", "..");
const VECTORS = join(ROOT, "docs", "trace", "schema", "test-vectors", "vault");
const FIXED_PASSPHRASE = "phase4-vault-fake-passphrase-01";

function loadFixture(): any {
  return JSON.parse(readFileSync(join(VECTORS, "vault-fake-run.json"), "utf8"));
}

function buildManifest(spec: any): WorkflowManifest {
  const policies: any[] = (spec.policies as any[]).map((p: any) => ({
    id: p.id,
    kind: p.kind,
    trigger: { capability: p.trigger_capability, bind: new Map() },
    requires: [],
    condition: null,
  }));
  const stages: any[] = (spec.stages as any[]).map((s: any) => ({
    id: s.id,
    prompt: "",
    reads: [],
    writes: s.writes.map((w: any) => ({ name: w.name, type: w.type, optional: w.optional })),
    requires: new Set(s.requires),
    transitions: s.transitions.map((t: any) => ({
      to: t.to,
      priority: t.priority,
      reason: t.reason,
      guard: { kind: t.guard_kind },
    })),
    execution: { kind: s.execution, capability: undefined, args: new Map() },
  }));
  const caps = new Set<string>();
  for (const st of stages) for (const c of st.requires as Set<string>) caps.add(c);
  for (const p of policies) caps.add(p.trigger.capability);
  return {
    workflowId: spec.workflow_id,
    entryStageId: spec.entry,
    exitStageIds: new Set(spec.exits as string[]),
    inputs: [],
    capabilities: caps,
    policies,
    stages,
  };
}

async function driveFixture(opts: {
  profile?: string;
  passphrase?: string | null;
  vaultCapture?: any;
} = {}): Promise<Uint8Array> {
  const fixture = loadFixture();
  const config = fixture.config;
  const clockAt = new Date(config.clock);
  const fixedClock = () => new Date(clockAt.getTime());
  const recorder = new TraceRecorder({
    profile: opts.profile ?? "replay",
    provenance: {
      frontend: "vault-fixture",
      target: "python",
      compilerVersion: "vault-fixture",
      irVersion: "0.1",
      irSha256: `sha256:${"ab".repeat(32)}`,
    },
    pathAliases: config.path_aliases,
    safePathAliases: config.safe_path_aliases,
    approvedMetrics: config.approved_metrics,
    secrets: config.secrets,
    traceId: config.trace_id,
    clock: fixedClock,
    vaultPassphrase: opts.passphrase !== undefined ? opts.passphrase : FIXED_PASSPHRASE,
    vaultCapture: opts.vaultCapture,
  });
  let lastVisit = "";
  let lastMid = "";
  let lastTid = "";
  const dummyTs = new Date("2020-01-01T00:00:00.000Z").toISOString();
  for (const op of fixture.ops as any[]) {
    const kind = op.op;
    if (kind === "begin_run") {
      recorder.beginRun(buildManifest(fixture.manifest));
    } else if (kind === "begin_stage_visit") {
      lastVisit = recorder.beginStageVisit(op.stage_id);
    } else if (kind === "record_run_inputs") {
      recorder.recordRunInputs(op.inputs);
    } else if (kind === "begin_model_call") {
      lastMid = recorder.beginModelCall();
    } else if (kind === "record_model_request") {
      recorder.recordModelRequest(lastMid, op.request);
    } else if (kind === "record_model_response_full") {
      recorder.recordModelResponse(lastMid, {
        responseBytes: op.response_bytes,
        toolCallCount: op.tool_call_count,
        response: op.response,
      });
    } else if (kind === "begin_tool_call") {
      lastTid = recorder.beginToolCall();
    } else if (kind === "record_tool_result") {
      recorder.recordToolResult(lastTid, op.result, op.args);
    } else if (kind === "record_transition_evaluation") {
      recorder.recordTransitionEvaluation(lastVisit, op.candidates);
    } else if (kind === "record_policy_evaluation") {
      recorder.recordPolicyEvaluation(lastVisit, op.policy_id, op.bound, op.outcome);
    } else if (kind === "observe") {
      const spec = op.event;
      const event: any = {
        kind: spec.kind,
        runId: "0".repeat(32),
        sequence: spec.sequence,
        timestamp: dummyTs,
        stageId: spec.stage_id,
        channel: spec.channel,
        text: spec.text,
        capability: spec.capability,
        toolName: spec.tool_name,
        args: spec.args,
        output: spec.output,
        result: spec.result,
        error: spec.error,
        transitionTo: spec.transition_to,
        metadata: spec.metadata ?? {},
      };
      recorder.observeWorkflowEvent(event);
    } else {
      throw new Error(`unknown vault op ${kind}`);
    }
  }
  return recorder.finishRun("complete");
}

function parseCentralMethods(data: Uint8Array): Map<string, number> {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let eocd = -1;
  const scanStart = Math.max(0, data.length - 65557);
  for (let i = data.length - 22; i >= scanStart; i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("EOCD missing");
  const entryCount = view.getUint16(eocd + 10, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  const map = new Map<string, number>();
  let cursor = cdOffset;
  const decoder = new TextDecoder();
  for (let n = 0; n < entryCount; n++) {
    const method = view.getUint16(cursor + 10, true);
    const nameLen = view.getUint16(cursor + 28, true);
    const extraLen = view.getUint16(cursor + 30, true);
    const commentLen = view.getUint16(cursor + 32, true);
    const nameBytes = data.subarray(cursor + 46, cursor + 46 + nameLen);
    const name = decoder.decode(nameBytes);
    map.set(name, method);
    cursor += 46 + nameLen + extraLen + commentLen;
  }
  return map;
}

describe("vault", () => {
  it("replay fixture matches frozen vault", async () => {
    const bytes = await driveFixture();
    const report = await verifyArchive(bytes);
    expect(report.ok, String(report.errors)).toBe(true);
    expect(report.replayability).toBe("taped-replay");
    expect(report.integrity).toBe("passed");
    expect(report.structural).toBe("passed");
    expect(report.semantic).toBe("not-evaluated");
    const entries = readArchiveEntries(bytes);
    expect(new Set(Object.keys(entries))).toEqual(
      new Set([
        "manifest.json",
        "public/workflow.graph.json",
        "public/events.ndjson",
        "public/summary.json",
        "private/vault.enc",
        "private/vault.meta.json",
        "integrity.json",
      ]),
    );
    // ZIP profile: only vault.enc is STORE
    const methods = parseCentralMethods(bytes);
    for (const [name, method] of methods.entries()) {
      if (name === "private/vault.enc") expect(method).toBe(0);
      else expect(method).toBe(8);
    }
    const manifest = JSON.parse(new TextDecoder().decode(entries["manifest.json"])) as any;
    expect(manifest.capture.profile).toBe("replay");
    expect(manifest.capture.vault_present).toBe(true);
    expect(manifest.capture.publication_eligible).toBe(false);
    const { records, report: unlockReport } = await unlockArchive(bytes, FIXED_PASSPHRASE);
    expect(unlockReport.semantic).toBe("passed");
    const frozen = readFileSync(join(VECTORS, "expected-vault-records.ndjson"));
    const actual = records.map((r) => canonicalStringify(r) + "\n").join("");
    expect(actual).toBe(frozen.toString("utf8"));
  });

  it("vault record types cover replay evidence", async () => {
    const bytes = await driveFixture();
    const { records } = await unlockArchive(bytes, FIXED_PASSPHRASE);
    const byType = new Map<string, any[]>();
    for (const r of records) {
      const t = r["record_type"] as string;
      let arr = byType.get(t);
      if (!arr) { arr = []; byType.set(t, arr); }
      arr.push(r);
    }
    for (const need of ["run_inputs","stage_snapshot","model_request","model_response","tool_result","transition_evaluation","policy_evaluation","full_workflow_ir"]) {
      expect(byType.has(need)).toBe(true);
    }
    expect(records.map((r) => r["record_id"])).toEqual(records.map((_, i) => `v-${i+1}`));
    const transitions = new Map<string, any>();
    for (const r of byType.get("transition_evaluation") ?? []) transitions.set(r["stage_visit_id"] as string, r);
    expect(transitions.get("s-1")["event_sequence"]).toBe(6);
    expect(transitions.get("s-1")["payload"]["candidates"][0]["matched"]).toBe(true);
    expect(transitions.get("s-2")["event_sequence"]).toBe(10);
  });

  it("hostile values never survive", async () => {
    const bytes = await driveFixture();
    const entries = readArchiveEntries(bytes);
    const cleartext = Object.entries(entries).filter(([n])=> n!=="private/vault.enc").map(([n,d])=> `${n}\n${new TextDecoder().decode(d)}`).join("\n");
    for (const forbidden of ["sk-vault-TEST-secret-9999","SHOULD-NEVER-APPEAR","/home/vault-user","private-chain-of-thought","Bearer "]) {
      expect(cleartext).not.toContain(forbidden);
    }
    const { records } = await unlockArchive(bytes, FIXED_PASSPHRASE);
    const vaultText = records.map((r) => JSON.stringify(r)).join("\n");
    for (const forbidden of ["sk-vault-TEST-secret-9999","SHOULD-NEVER-APPEAR","/home/vault-user","Bearer "]) {
      expect(vaultText).not.toContain(forbidden);
    }
    expect(vaultText).not.toContain("private-chain-of-thought");
    expect(vaultText).toContain("$workspace/a.txt");
    expect(vaultText).toContain("synthetic-vault");
  });

  it("reasoning opt-in", async () => {
    const bytes = await driveFixture({ vaultCapture: { includeReasoning: true } });
    const { records, report } = await unlockArchive(bytes, FIXED_PASSPHRASE);
    expect(report.semantic).toBe("passed");
    const responses = records.filter((r) => r["record_type"] === "model_response");
    expect(responses.length).toBeGreaterThan(0);
    expect((responses[0]["payload"] as any)["reasoning"]).toBe("private-chain-of-thought");
  });

  it("wrong passphrase fails closed", async () => {
    const bytes = await driveFixture();
    const { records, report } = await unlockArchive(bytes, "wrong-passphrase");
    expect(records).toEqual([]);
    expect(report.semantic).toBe("failed");
    expect(report.errors).toEqual(["vault unlock failed"]);
  });

  it("modified ciphertext fails closed", async () => {
    const bytes = await driveFixture();
    const entries = readArchiveEntries(bytes);
    const sealed = new Uint8Array(entries["private/vault.enc"]);
    sealed[0] ^= 1;
    // Rebuild archive with tampered ciphertext but same other entries (need to preserve ZIP profile)
    const { writeArchive } = await import("../trace.js");
    const tamperedEntries: Record<string, Uint8Array> = { ...entries, ["private/vault.enc"]: sealed };
    const tampered = writeArchive(tamperedEntries);
    const { records, report } = await unlockArchive(tampered, FIXED_PASSPHRASE);
    expect(records).toEqual([]);
    expect(report.semantic).toBe("failed");
  });

  it("replay requires passphrase", () => {
    const clock = () => new Date("2026-03-04T05:06:07.000Z");
    expect(() => new TraceRecorder({ profile: "replay", clock })).toThrow(TraceError);
    expect(() => new TraceRecorder({ profile: "audit", vaultPassphrase: "pw", clock } as any)).toThrow(TraceError);
    expect(() => new TraceRecorder({ profile: "publication" as any, clock })).toThrow(TraceError);
  });

  it("audit profile has no vault", async () => {
    const fixture = loadFixture();
    const clockAt = new Date(fixture.config.clock);
    const recorder = new TraceRecorder({
      profile: "audit",
      clock: () => new Date(clockAt.getTime()),
    });
    // need manifest
    recorder.beginRun(buildManifest(fixture.manifest));
    const bytes = await recorder.finishRun("complete");
    const report = await verifyArchive(bytes);
    expect(report.ok).toBe(true);
    expect(report.replayability).toBe("playback-only");
    const { records, report: unlockReport } = await unlockArchive(bytes, FIXED_PASSPHRASE);
    expect(records).toEqual([]);
    expect(unlockReport.semantic).toBe("failed");
  });

  it("retry after completed reuses the attempt id", async () => {
    // Regression mirror of the Python test of the same name: a retry emitted
    // after model_completed consumed the call id must reuse that id (which
    // already has vault evidence) instead of synthesizing a dangling one.
    const clockAt = new Date("2026-03-04T05:06:07.000Z");
    const recorder = new TraceRecorder({
      profile: "replay",
      provenance: {
        frontend: "retry-regression",
        target: "web",
        compilerVersion: "retry-regression",
        irVersion: "0.1",
        irSha256: `sha256:${"ab".repeat(32)}`,
      },
      traceId: "ab".repeat(16),
      clock: () => new Date(clockAt.getTime()),
      vaultPassphrase: FIXED_PASSPHRASE,
    });
    const manifest: WorkflowManifest = {
      workflowId: "MiniRetry",
      entryStageId: "A",
      exitStageIds: new Set(["A"]),
      inputs: [],
      capabilities: new Set(),
      policies: [],
      stages: [
        {
          id: "A",
          prompt: "",
          reads: [],
          writes: [{ name: "score", type: "number", optional: false }],
          requires: new Set(),
          transitions: [],
          execution: { kind: "model", capability: undefined, args: new Map() },
        },
      ],
    };
    const dummyTs = "2020-01-01T00:00:00.000Z";
    const observe = (kind: string, sequence: number, extra: Record<string, unknown> = {}) => {
      recorder.observeWorkflowEvent({
        kind,
        runId: "c".repeat(32),
        sequence,
        timestamp: dummyTs,
        stageId: "A",
        metadata: {},
        ...extra,
      } as any);
    };
    const attempt = (expectedId: string, score: number) => {
      const begun = recorder.beginModelCall();
      expect(begun).toBe(expectedId);
      recorder.recordModelRequest(begun, {
        messages: [{ role: "user", content: "score" }],
        tools: [],
        output_schema: {},
      });
      recorder.recordModelResponse(begun, {
        responseBytes: 16,
        toolCallCount: 0,
        response: { content: JSON.stringify({ score }), tool_calls: [], usage: {} },
      });
    };
    recorder.beginRun(manifest);
    observe("run_started", 1);
    recorder.beginStageVisit("A");
    observe("stage_started", 2);
    attempt("m-1", 0.1);
    observe("model_completed", 3);
    // Tool-error retry arrives with an empty pending queue (real runtime
    // order: completed consumed m-1 before the retry was emitted).
    observe("model_retry", 4, {
      metadata: { attempt: 1, max_retries: 3, category: "tool_call" },
    });
    attempt("m-2", 0.9);
    observe("model_completed", 5);
    observe("stage_completed", 6, { output: { score: 0.9 } });
    observe("run_completed", 7);
    const bytes = await recorder.finishRun("complete");
    const entries = readArchiveEntries(bytes);
    const ledger = new TextDecoder()
      .decode(entries["public/events.ndjson"])
      .split("\n")
      .filter((l) => l.trim() !== "")
      .map((l) => JSON.parse(l) as any);
    const bySeq = new Map(ledger.map((e) => [e.sequence, e]));
    expect(bySeq.get(3).model_call_id).toBe("m-1");
    expect(bySeq.get(4).model_call_id).toBe(
      "m-1",
    );
    expect(bySeq.get(5).model_call_id).toBe("m-2");
    const report = await verifyArchive(bytes);
    expect(report.ok, String(report.errors)).toBe(true);
    const { records, report: unlockReport } = await unlockArchive(bytes, FIXED_PASSPHRASE);
    expect(unlockReport.ok, String(unlockReport.errors)).toBe(true);
    expect(unlockReport.semantic).toBe("passed");
    expect(
      records.filter((r) => r["record_type"] === "model_request").map((r) => r["model_call_id"]),
    ).toEqual(["m-1", "m-2"]);
  });
});
