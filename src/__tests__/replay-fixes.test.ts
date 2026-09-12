import { describe, expect, it } from "vitest";

import { WorkflowRuntime } from "../runtime.js";
import { ModelStageExecutor } from "../models.js";
import { ToolRegistry } from "../tools.js";
import type { Tool } from "../tools.js";
import { TraceRecorder } from "../trace.js";
import { replayTrace, _testHelpers } from "../replay.js";
import type { WorkflowManifest } from "../manifest.js";
import { expr, makeManifest, makeStage, makeWrite, ref } from "./helpers.js";

// ---------------------------------------------------------------------------
// Placeholder unit test (all marker types + nesting)
// ---------------------------------------------------------------------------

describe("replay placeholders", () => {
  it("covers all marker types and nesting", () => {
    const { unmarkFixture } = _testHelpers as any;
    function marker(valueType: string, length: number | null = null): Record<string, unknown> {
      const inner: Record<string, unknown> = { token: "r-1", reason: "x", value_type: valueType };
      if (length !== null) (inner as any).length = length;
      return { $redacted: inner };
    }
    expect(unmarkFixture(marker("string", 3))).toBe("???");
    expect(unmarkFixture(marker("string"))).toBe("");
    expect(unmarkFixture(marker("number", 5))).toBe(0);
    expect(unmarkFixture(marker("boolean"))).toBe(false);
    expect(unmarkFixture(marker("array", 2))).toEqual([]);
    expect(unmarkFixture(marker("object"))).toEqual({});
    expect(unmarkFixture(marker("null"))).toBeNull();
    const nested = { a: [marker("string", 1)], b: { c: marker("number") }, d: "kept" };
    expect(unmarkFixture(nested)).toEqual({ a: ["?"], b: { c: 0 }, d: "kept" });
    // Unknown/other value_type falls through to null
    expect(unmarkFixture(marker("binary"))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Policy tape e2e (model tool call + deny policy)
// ---------------------------------------------------------------------------

class ToolCallAdapter {
  calls: unknown[] = [];
  private step = 0;
  async complete(request: any) {
    this.calls.push(request);
    this.step += 1;
    if (this.step === 1) {
      return {
        content: null,
        toolCalls: [{ id: "call-1", name: "run_shell", arguments: { command: "echo /home/u/build-ok python" } }],
        reasoning: null,
      };
    }
    return { content: '{"done": true}', toolCalls: [], reasoning: null };
  }
}

function scopedRegistry(): ToolRegistry {
  const shell: Tool = {
    name: "run_shell",
    capability: "os.shell",
    description: "shell",
    inputSchema: { command: "string" },
    handler: async (args) => ({ output: "ok", command: String(args.command) }),
  };
  return new ToolRegistry([shell]);
}

function scopedManifest(): WorkflowManifest {
  return makeManifest(
    [
      makeStage("M", {
        prompt: "",
        writes: [makeWrite("done", "bool")],
        requires: new Set(["os.shell"]),
        transitions: [],
        execution: { kind: "model" as const },
      }),
    ],
    {
      workflowId: "ReplayTape",
      entryId: "M",
      exitIds: new Set(["M"]),
      inputs: [],
      capabilities: new Set(["os.shell"]),
      policies: [
        {
          id: "deny os.shell without python",
          kind: "deny" as const,
          trigger: { capability: "os.shell", bind: new Map([["command", "command"]]) },
          requires: [],
          condition: expr.not(expr.methodCall(expr.ref(ref.bound("command")), "contains", expr.literal("string", "python"))),
        },
      ],
    },
  );
}

describe("policy tape e2e", () => {
  it("reproduces recorded allow via tape despite scrubbed placeholder", async () => {
    const adapter = new ToolCallAdapter();
    const registry = scopedRegistry();
    const runtime = new WorkflowRuntime({
      manifest: scopedManifest(),
      tools: registry,
      stageExecutor: new ModelStageExecutor({ model: adapter as any, tools: registry }),
    });
    const recorder = new TraceRecorder({
      profile: "replay",
      provenance: { frontend: "replay-e2e", target: "web", compilerVersion: "replay-e2e", irVersion: "0.1", irSha256: `sha256:${"cd".repeat(32)}` },
      pathAliases: { $workspace: "/work" },
      safePathAliases: ["$workspace"],
      vaultPassphrase: "replay-e2e-passphrase",
    });
    const result = await runtime.run({}, { traceRecorder: recorder });
    expect((result.output as any).done).toBe(true);
    expect(adapter.calls.length).toBe(2);
    const liveCalls = adapter.calls.length;
    const bytes = recorder.archiveBytes!;
    expect(bytes).not.toBeNull();
    const report = await replayTrace(bytes, "replay-e2e-passphrase");
    expect(report.matched, String(report.divergences)).toBe(true);
    expect(report.replayedStatus).toBe("complete");
    expect(report.verification.semantic).toBe("passed");
    // Live fakes untouched by replay
    expect(adapter.calls.length).toBe(liveCalls);
  });
});

// ---------------------------------------------------------------------------
// Projection-kept test (stage_completed with stderr/stdout)
// ---------------------------------------------------------------------------

describe("projection kept", () => {
  it("stage_completed with stderr/stdout is kept with markers", async () => {
    const recorder = new TraceRecorder({
      profile: "audit",
      traceId: "cd".repeat(16),
      clock: () => new Date("2026-03-04T05:06:07.000Z"),
    });
    const manifest: WorkflowManifest = makeManifest(
      [
        makeStage("A", {
          writes: [
            makeWrite("ok", "bool"),
            makeWrite("report", "string"),
            makeWrite("stderr", "string"),
            makeWrite("stdout", "string"),
          ],
        }),
      ],
      {
        workflowId: "MiniStderr",
        entryId: "A",
        exitIds: new Set(["A"]),
        inputs: [],
        capabilities: new Set(),
      },
    );
    recorder.beginRun(manifest);
    const dummyTs = "2020-01-01T00:00:00.000Z";
    const observe = (kind: string, seq: number, extra: Record<string, unknown> = {}) => {
      recorder.observeWorkflowEvent({
        kind,
        runId: "c".repeat(32),
        sequence: seq,
        timestamp: dummyTs,
        stageId: "A",
        metadata: {},
        ...extra,
      } as any);
    };
    observe("run_started", 1);
    recorder.beginStageVisit("A");
    observe("stage_started", 2);
    observe("stage_completed", 3, {
      output: {
        ok: false,
        report: "research run failed (exit=1)",
        stderr: "bwrap: Creating new namespace failed\n",
        stdout: "",
      },
    });
    observe("run_completed", 4);
    const bytes = await recorder.finishRun("complete");
    const { verifyArchive, readArchiveEntries } = await import("../trace.js");
    const report = await verifyArchive(bytes);
    expect(report.ok, String(report.errors)).toBe(true);
    const entries = readArchiveEntries(bytes);
    const ledger = new TextDecoder().decode(entries["public/events.ndjson"]).split("\n").filter((l) => l.trim() !== "").map((l) => JSON.parse(l));
    const completed = ledger.filter((e: any) => e.kind === "stage_completed");
    expect(completed).toHaveLength(1);
    const output = completed[0].output as Record<string, unknown>;
    for (const key of ["report", "stderr", "stdout"]) {
      const marker = output[key] as Record<string, unknown>;
      expect(typeof marker).toBe("object");
      expect("$redacted" in marker).toBe(true);
    }
    expect(new TextDecoder().decode(entries["public/events.ndjson"])).not.toContain("bwrap");
  });
});

// ---------------------------------------------------------------------------
// setMarker arrays: precise marker inside array, not whole-value
// ---------------------------------------------------------------------------

describe("setMarker arrays", () => {
  it("marks array element precisely, not whole value", async () => {
    // Use vault scrubbing via recordToolResult with array containing home path
    const recorder = new TraceRecorder({
      profile: "replay",
      traceId: "ab".repeat(16),
      clock: () => new Date("2026-03-04T05:06:07.000Z"),
      vaultPassphrase: "test-passphrase-1234",
    });
    const manifest: WorkflowManifest = makeManifest(
      [
        makeStage("A", {
          writes: [makeWrite("out", "json")],
          requires: new Set(["os.shell"]),
          transitions: [],
          execution: { kind: "model" as const },
        }),
      ],
      {
        workflowId: "ArrayMarker",
        entryId: "A",
        exitIds: new Set(["A"]),
        inputs: [],
        capabilities: new Set(["os.shell"]),
      },
    );
    recorder.beginRun(manifest);
    const visit = recorder.beginStageVisit("A");
    const toolId = recorder.beginToolCall("A", visit);
    // Emulate ToolRegistry pre-store for vault: need to populate openToolCalls before record
    // The recorder's observeWorkflowEvent would normally populate openToolCalls on tool_call_started.
    // Simulate that so recordToolResult can find capability.
    (recorder as unknown as { openToolCalls: Map<string, Record<string, unknown>> }).openToolCalls.set(toolId, {
      capability: "os.shell",
      tool_name: "run_shell",
      args: { command: "x" },
      stage_visit_id: visit,
    });
    // Record a tool result where result is an array containing a credential and a home path
    // Use a credential pattern that forces a $redacted marker inside the array array
    const secretArray = ["sk-ant-test1234567890abcdef-secret", "safe", "/home/secret-user/file"];
    recorder.recordToolResult(toolId, secretArray);
    // Also test via direct setMarker on a crafted ledger record containing array
    // to prove public ledger handling: create a dummy record with output array
    const dummyRecorder = new TraceRecorder({
      traceId: "cd".repeat(16),
      clock: () => new Date("2026-03-04T05:06:07.000Z"),
    });
    dummyRecorder.beginRun(manifest);
    dummyRecorder.beginStageVisit("A");
    // Craft a record that would be scanned: stage_completed with array value
    // We need approvedMetrics to keep array visible, but string[] not allowed as metric.
    // Instead test setMarker directly via private method.
    const testRecord: Record<string, unknown> = {
      kind: "stage_completed",
      run_id: "cd".repeat(16),
      timestamp: new Date().toISOString(),
      stage_id: "A",
      stage_visit_id: "s-1",
      output: { findings: ["/home/secret-user/file", "ok"] },
      redacted_fields: [],
    };
    // Use registry with secret that triggers home_path finding
    // Directly invoke setMarker for pointer inside array
    (dummyRecorder as unknown as { setMarker: (a: any, b: string, c: string) => void }).setMarker(testRecord, "/output/findings/0", "absolute_path");
    expect((testRecord.output as Record<string, unknown>).findings).toBeDefined();
    const findings = (testRecord.output as Record<string, unknown>).findings as unknown[];
    expect(Array.isArray(findings)).toBe(true);
    expect((findings[0] as Record<string, unknown>)["$redacted"]).toBeDefined();
    expect(findings[1]).toBe("ok");
    expect(testRecord.redacted_fields).toContain("/output/findings/0");
    // Ensure vault precise marker: the vault record's payload result array element should be markered/ref precisely, not whole result
    const vaultRecords = (recorder as unknown as { vaultRecords: Record<string, unknown>[] }).vaultRecords;
    const last = vaultRecords[vaultRecords.length - 1];
    const payload = last.payload as Record<string, unknown>;
    const result = payload.result as unknown;
    if (Array.isArray(result)) {
      // First element was credential -> should be $redacted marker
      const first = result[0] as Record<string, unknown>;
      expect(first !== null && typeof first === "object" && "$redacted" in first).toBe(true);
      expect(result[1]).toBe("safe");
      // Third element was home path -> should be opaque ref "path-1" or marker, but precisely at index 2
      const third = result[2];
      const isPathRef = typeof third === "string" && third.startsWith("path-");
      const isMarker = third !== null && typeof third === "object" && "$redacted" in (third as Record<string, unknown>);
      expect(isPathRef || isMarker).toBe(true);
    } else {
      throw new Error("vault result not array");
    }
    expect((payload as Record<string, unknown>)["$redacted"]).toBeUndefined();
  });
});
