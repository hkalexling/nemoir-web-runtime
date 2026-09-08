/**
 * Cross-language parity: the shared fixture must project byte-identical ledgers.
 *
 * Drives `TraceRecorder` through `docs/trace/schema/test-vectors/parity/fake-run.json`
 * (hooks + observations, fixed clock + trace id) and asserts byte equality with
 * the frozen `expected-ledger.ndjson` / `expected-graph.json`. The Python suite
 * (`python/nemoir-runtime/tests/test_parity.py`) asserts the same files, so both
 * recorders provably emit identical canonical bytes for one logical run.
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import type { WorkflowManifest } from "../manifest.js";
import { TraceRecorder, readArchiveEntries, verifyArchive } from "../trace.js";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..", "..", "..", "..");
const PARITY = join(ROOT, "docs", "trace", "schema", "test-vectors", "parity");

interface FixtureManifest {
  workflow_id: string;
  entry: string;
  exits: string[];
  policies: { id: string; kind: string; trigger_capability: string }[];
  stages: {
    id: string;
    execution: string;
    requires: string[];
    writes: { name: string; type: string; optional: boolean }[];
    transitions: { to: string; priority: number; reason: string; guard_kind: string }[];
  }[];
}

interface Fixture {
  manifest: FixtureManifest;
  config: {
    trace_id: string;
    clock: string;
    path_aliases: Record<string, string>;
    safe_path_aliases: string[];
    approved_metrics: string[];
    secrets: string[];
  };
  ops: Record<string, unknown>[];
}

function buildManifest(spec: FixtureManifest): WorkflowManifest {
  return {
    workflowId: spec.workflow_id,
    entryStageId: spec.entry,
    exitStageIds: new Set(spec.exits),
    inputs: [],
    capabilities: new Set([
      ...spec.stages.flatMap((s) => s.requires),
      ...spec.policies.map((p) => p.trigger_capability),
    ]),
    policies: spec.policies.map((p) => ({
      id: p.id,
      kind: p.kind as "before" | "deny",
      trigger: { capability: p.trigger_capability, bind: new Map() },
      requires: [],
      condition: null,
    })),
    stages: spec.stages.map((s) => ({
      id: s.id,
      prompt: "",
      reads: [],
      writes: s.writes.map((w) => ({ name: w.name, type: w.type, optional: w.optional })),
      requires: new Set(s.requires),
      transitions: s.transitions.map((t) => ({
        to: t.to,
        priority: t.priority,
        reason: t.reason,
        guard: { kind: t.guard_kind } as { kind: "always" },
      })),
      execution: { kind: s.execution } as { kind: "model" | "tool" },
    })),
  };
}

function errorWithTypeName(typeName: string): unknown {
  const Cls = class extends Error {};
  Object.defineProperty(Cls, "name", { value: typeName });
  return new Cls("parity");
}

describe("cross-language parity", () => {
  it("matches the frozen parity vectors byte for byte", async () => {
    const fixture = JSON.parse(readFileSync(join(PARITY, "fake-run.json"), "utf8")) as Fixture;
    const fixedClock = new Date(fixture.config.clock);
    const recorder = new TraceRecorder({
      profile: "audit",
      provenance: {
        frontend: "parity",
        target: "parity",
        compilerVersion: "parity",
        irVersion: "0.1",
        irSha256: `sha256:${"ef".repeat(32)}`,
      },
      pathAliases: fixture.config.path_aliases,
      safePathAliases: fixture.config.safe_path_aliases,
      approvedMetrics: fixture.config.approved_metrics,
      secrets: fixture.config.secrets,
      traceId: fixture.config.trace_id,
      clock: () => new Date(fixedClock.getTime()),
    });

    let lastMid = "";
    let lastTid = "";
    const dummyTimestamp = new Date("2020-01-01T00:00:00.000Z").toISOString();
    for (const op of fixture.ops) {
      const kind = op.op as string;
      if (kind === "begin_run") {
        recorder.beginRun(buildManifest(fixture.manifest));
      } else if (kind === "begin_stage_visit") {
        recorder.beginStageVisit(op.stage_id as string);
      } else if (kind === "begin_model_call") {
        lastMid = recorder.beginModelCall();
      } else if (kind === "record_model_response") {
        recorder.recordModelResponse(lastMid, {
          responseBytes: op.response_bytes as number,
          toolCallCount: op.tool_call_count as number,
        });
      } else if (kind === "begin_tool_call") {
        lastTid = recorder.beginToolCall();
      } else if (kind === "record_tool_result") {
        recorder.recordToolResult(lastTid, op.result as unknown);
      } else if (kind === "record_tool_error") {
        recorder.recordToolError(lastTid, errorWithTypeName(op.error_type as string));
      } else if (kind === "observe") {
        const spec = op.event as Record<string, unknown>;
        recorder.observeWorkflowEvent({
          kind: spec.kind as never,
          runId: "0".repeat(32),
          sequence: spec.sequence as number,
          timestamp: dummyTimestamp,
          stageId: spec.stage_id as string | undefined,
          channel: spec.channel as never,
          text: spec.text as string | undefined,
          capability: spec.capability as string | undefined,
          toolName: spec.tool_name as string | undefined,
          args: spec.args as Record<string, unknown> | undefined,
          output: spec.output as Record<string, unknown> | undefined,
          result: spec.result,
          error: spec.error as string | undefined,
          transitionTo: spec.transition_to as string | undefined,
          metadata: (spec.metadata ?? {}) as Record<string, unknown>,
        });
      } else {
        throw new Error(`unknown parity op ${kind}`);
      }
    }

    const bytes = await recorder.finishRun("complete");
    const entries = readArchiveEntries(bytes);
    const expectedLedger = readFileSync(join(PARITY, "expected-ledger.ndjson"));
    const expectedGraph = readFileSync(join(PARITY, "expected-graph.json"));
    expect(Buffer.from(entries["public/events.ndjson"]).equals(expectedLedger)).toBe(true);
    expect(Buffer.from(entries["public/workflow.graph.json"]).equals(expectedGraph)).toBe(true);
    const report = await verifyArchive(bytes);
    expect(report.errors).toEqual([]);
    expect(report.ok).toBe(true);
  });
});
