import { describe, expect, it } from "vitest";

import { WorkflowRuntime } from "../runtime.js";
import { ModelStageExecutor } from "../models.js";
import { ToolRegistry } from "../tools.js";
import type { Tool, ToolContext } from "../tools.js";
import { TraceRecorder } from "../trace.js";
import { replayTrace, TapedModelAdapter, TapedReplayError, TapedToolRegistry } from "../replay.js";
import type { ModelRequest } from "../model-contract.js";
import type { WorkflowManifest } from "../manifest.js";

class StageAdapter {
  calls: ModelRequest[] = [];
  constructor(private content = '{"score": 0.9}') {}
  async complete(request: ModelRequest) {
    this.calls.push(request);
    return { content: this.content, toolCalls: [], reasoning: null as any };
  }
}

function buildManifest(deny: boolean): WorkflowManifest {
  const literal = (v: unknown) => ({ kind: "literal" as const, type: typeof v === "boolean" ? "bool" : "string", value: v } as any);
  return {
    workflowId: "ReplayE2E",
    entryStageId: "A",
    exitStageIds: new Set(["C"]),
    inputs: [{ id: "topic", type: "string" }],
    capabilities: new Set(["fs.read", "fs.write"]),
    policies: deny ? [
      { id: "deny fs.write if guard", kind: "deny" as const, trigger: { capability: "fs.write", bind: new Map() }, requires: [], condition: literal(true) }
    ] : [
      { id: "deny fs.write if guard", kind: "deny" as const, trigger: { capability: "fs.write", bind: new Map() }, requires: [], condition: literal(false) }
    ],
    stages: [
      {
        id: "A",
        prompt: "",
        reads: [],
        writes: [{ name: "text", type: "string", optional: false }],
        requires: new Set(["fs.read"]),
        transitions: [{ to: "B", priority: 0, reason: "explicit_transition", guard: { kind: "always" as const } }],
        execution: { kind: "tool" as const, capability: "fs.read", args: new Map([["path", literal("/work/a.txt") as any]]) },
      },
      {
        id: "B",
        prompt: "",
        reads: [],
        writes: [{ name: "score", type: "number", optional: false }],
        requires: new Set(),
        transitions: [{ to: "C", priority: 0, reason: "explicit_transition", guard: { kind: "always" as const } }],
        execution: { kind: "model" as const },
      },
      {
        id: "C",
        prompt: "",
        reads: [],
        writes: [{ name: "done", type: "bool", optional: false }],
        requires: new Set(["fs.write"]),
        transitions: [],
        execution: { kind: "tool" as const, capability: "fs.write", args: new Map([["path", literal("/work/out.txt") as any], ["content", literal("data") as any]]) },
      },
    ],
  };
}

function registry(calls: [string, string][]): ToolRegistry {
  const reader: Tool = {
    name: "reader",
    capability: "fs.read",
    description: "r",
    inputSchema: { path: "string" },
    handler: async (args) => { calls.push(["fs.read", String(args.path)]); return { text: "hello" }; },
  };
  const writer: Tool = {
    name: "writer",
    capability: "fs.write",
    description: "w",
    inputSchema: { path: "string", content: "string" },
    handler: async (args) => { calls.push(["fs.write", String(args.path)]); return { done: true }; },
  };
  return new ToolRegistry([reader, writer]);
}

function compositeExecutor(adapter: StageAdapter, reg: ToolRegistry): any {
  const modelExec = new ModelStageExecutor({ model: adapter as any, tools: reg });
  return {
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
}

async function recordTmp(deny: boolean): Promise<{ bytes: Uint8Array; adapter: StageAdapter; calls: [string, string][] }> {
  const adapter = new StageAdapter();
  const calls: [string, string][] = [];
  const reg = registry(calls);
  const runtime = new WorkflowRuntime({ manifest: buildManifest(deny), tools: reg, stageExecutor: compositeExecutor(adapter, reg) });
  const recorder = new TraceRecorder({
    profile: "replay",
    provenance: { frontend: "replay-e2e", target: "web", compilerVersion: "replay-e2e", irVersion: "0.1", irSha256: `sha256:${"cd".repeat(32)}` },
    pathAliases: { $workspace: "/work" },
    safePathAliases: ["$workspace"],
    vaultPassphrase: "replay-e2e-passphrase",
  });
  if (deny) {
    await expect(runtime.run({ topic: "replay-e2e" }, { traceRecorder: recorder })).rejects.toThrow();
  } else {
    const result = await runtime.run({ topic: "replay-e2e" }, { traceRecorder: recorder });
    expect((result.output as any).done).toBe(true);
  }
  const bytes = recorder.archiveBytes!;
  expect(bytes).not.toBeNull();
  return { bytes, adapter, calls };
}

describe("replay", () => {
  it("taped replay matches recorded path", async () => {
    const { bytes, adapter, calls } = await recordTmp(false);
    expect(adapter.calls.length).toBeGreaterThan(0);
    expect(calls.length).toBe(2);
    const liveModelCalls = adapter.calls.length;
    const liveToolCalls = calls.length;
    const report = await replayTrace(bytes, "replay-e2e-passphrase");
    expect(report.matched, String(report.divergences)).toBe(true);
    expect(report.divergences).toEqual([]);
    expect(report.replayedStatus).toBe("complete");
    expect(report.steps).toBe(3);
    expect(report.verification.semantic).toBe("passed");
    expect(adapter.calls.length).toBe(liveModelCalls);
    expect(calls.length).toBe(liveToolCalls);
  });

  it("taped replay matches failure path", async () => {
    const { bytes } = await recordTmp(true);
    const report = await replayTrace(bytes, "replay-e2e-passphrase");
    expect(report.matched, String(report.divergences)).toBe(true);
    expect(report.replayedStatus).toBe("failed");
  });

  it("taped replay refuses audit archive", async () => {
    const adapter = new StageAdapter();
    const calls: [string, string][] = [];
    const reg = registry(calls);
    const runtime = new WorkflowRuntime({ manifest: buildManifest(false), tools: reg, stageExecutor: compositeExecutor(adapter, reg) });
    const recorder = new TraceRecorder({});
    const result = await runtime.run({ topic: "replay-e2e" }, { traceRecorder: recorder });
    expect((result.output as any).done).toBe(true);
    const bytes = recorder.archiveBytes!;
    const report = await replayTrace(bytes, "replay-e2e-passphrase");
    expect(report.matched).toBe(false);
    expect(report.divergences.some((d) => d.includes("no replay vault"))).toBe(true);
    expect(report.verification.replayability).toBe("playback-only");
  });

  it("taped replay wrong passphrase", async () => {
    const { bytes } = await recordTmp(false);
    const report = await replayTrace(bytes, "wrong-passphrase");
    expect(report.matched).toBe(false);
    expect(report.divergences).toEqual(["vault unlock failed"]);
  });

  it("taped fixtures fail closed", async () => {
    const model = new TapedModelAdapter(new Map());
    await expect(model.complete({ stageId: "B", messages: [], tools: [], outputSchema: {}, options: {} } as any)).rejects.toThrow(TapedReplayError);
    const tools = new TapedToolRegistry([]);
    await expect(tools.call("fs.read", {}, { workflowId: "w", stageId: "A", inputs: {}, metadata: {} } as ToolContext)).rejects.toThrow(TapedReplayError);
  });

  it("taped stubs skip catalog validation for incomplete schemas", async () => {
    // Regression: `_validateTools` was a dead static no-op, so a stub whose
    // schema lacked catalog-required params (incomplete early vault) threw
    // ToolValidationError instead of replaying.
    const fixtures = [
      {
        record_type: "tool_result",
        capability: "fs.read",
        tool_name: "read_file",
        payload: { args: { path: "x" }, result: { ok: true } },
      },
    ];
    const tools = new TapedToolRegistry(fixtures, new Map([["fs.read", { inputs: {}, outputs: {} }]]));
    const out = await tools.call(
      "fs.read",
      { path: "x" },
      { workflowId: "w", stageId: "A", inputs: {}, metadata: {} } as ToolContext,
    );
    expect(out).toEqual({ ok: true });
  });

  it("live registries still validate against the capability catalog", () => {
    expect(
      () =>
        new ToolRegistry([
          { name: "bad", capability: "fs.read", description: "", inputSchema: {}, handler: async () => ({}) },
        ]),
    ).toThrow(/missing required parameter/);
  });
});
