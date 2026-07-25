/**
 * ModelStageExecutor tests.
 *
 * Ports the web-safe subset of
 * `python/nemoir-runtime/tests/test_model_stage_executor.py`:
 * content-only stages, tool-call loops, retry behavior, max_tool_rounds,
 * streaming, numeric output validation.
 */

import { describe, it, expect } from "vitest";
import { ModelStageExecutor } from "../models.js";
import { resolveRunOptions } from "../runtime-types.js";
import { ToolRegistry, type Tool } from "../tools.js";
import { fakeAdapter, fakeStreamingAdapter } from "./helpers.js";
import type { ModelResponse } from "../model-contract.js";
import type { StageContext } from "../runtime.js";
import { WorkflowEventEmitter } from "../events.js";
import { ModelOutputValidationError } from "../errors.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCtx(opts: {
  writes?: { name: string; type: string; optional?: boolean }[];
  allowedCapabilities?: Set<string>;
  readableContext?: Record<string, unknown>;
  options?: Record<string, unknown> | undefined;
  emitter?: WorkflowEventEmitter | null;
  toolCallsLog?: Array<[string, Record<string, unknown>]>;
}): StageContext {
  const writes = (opts.writes ?? []).map((w) => ({
    name: w.name,
    type: w.type,
    optional: w.optional ?? false,
  }));

  const toolCallsLog = opts.toolCallsLog ?? [];

  const emitter = opts.emitter ?? null;

  async function callTool(
    capability: string,
    args: Record<string, unknown>,
  ): Promise<string> {
    toolCallsLog.push([capability, args]);
    return "result";
  }

  return {
    workflowId: "TestWorkflow",
    stage: {
      id: "Test",
      prompt: "test prompt",
      reads: [],
      writes,
      requires: opts.allowedCapabilities ?? new Set(),
      transitions: [],
      execution: { kind: "model" },
    },
    inputs: {},
    readableContext: opts.readableContext ?? {},
    allowedCapabilities: opts.allowedCapabilities ?? new Set(),
    options: resolveRunOptions(opts.options as Partial<import("../runtime-types.js").RunOptions>),
    callTool,
    eventEmitter: emitter,
  };
}

function readTool(): Tool {
  return {
    name: "read",
    capability: "user.elicit",
    description: "Read",
    inputSchema: { question: "string" },
    handler: async () => "read-ok",
  };
}

// ---------------------------------------------------------------------------
// Content-only stage execution
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — content-only stages", () => {
  it("returns parsed output for valid JSON", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: '{"summary": "done"}' },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
    expect(calls.length).toBe(1);
  });

  it("throws on invalid JSON with maxModelRetries=0", async () => {
    const { adapter } = fakeAdapter([{ content: "not json" }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      options: { maxModelRetries: 0 },
    });
    await expect(executor.execute(ctx)).rejects.toThrow(ModelOutputValidationError);
  });

  it("throws on missing required field with maxModelRetries=0", async () => {
    const { adapter } = fakeAdapter([{ content: "{}" }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      options: { maxModelRetries: 0 },
    });
    await expect(executor.execute(ctx)).rejects.toThrow(ModelOutputValidationError);
  });

  it("throws on unknown output field with maxModelRetries=0", async () => {
    const { adapter } = fakeAdapter([{ content: '{"summary": "ok", "extra": 1}' }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      options: { maxModelRetries: 0 },
    });
    await expect(executor.execute(ctx)).rejects.toThrow(ModelOutputValidationError);
  });

  it("throws on non-object JSON with maxModelRetries=0", async () => {
    const { adapter } = fakeAdapter([{ content: "[1, 2]" }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      options: { maxModelRetries: 0 },
    });
    await expect(executor.execute(ctx)).rejects.toThrow(ModelOutputValidationError);
  });
});

// ---------------------------------------------------------------------------
// Retry behavior
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — retries", () => {
  it("retries invalid JSON then succeeds", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: "not json" },
      { content: '{"summary": "done"}' },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
    expect(calls.length).toBe(2);
  });

  it("exhausts maxModelRetries and raises", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: "not json" },
      { content: "also not json" },
      { content: "still not json" },
      { content: "yet again" },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      options: { maxModelRetries: 2 },
    });
    await expect(executor.execute(ctx)).rejects.toThrow(ModelOutputValidationError);
    // Initial + 2 retries = 3 calls
    expect(calls.length).toBe(3);
  });

  it("maxModelRetries=0 preserves hard-fail behavior", async () => {
    const { adapter, calls } = fakeAdapter([{ content: "not json" }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      options: { maxModelRetries: 0 },
    });
    await expect(executor.execute(ctx)).rejects.toThrow(ModelOutputValidationError);
    expect(calls.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Tool-call loop (native protocol)
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — native tool calls", () => {
  it("executes a single tool call then returns output", async () => {
    const { adapter } = fakeAdapter([
      {
        content: null,
        toolCalls: [{ id: "c1", name: "read", arguments: { question: "hi" } }],
      },
      { content: '{"summary": "done"}' },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([readTool()]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      allowedCapabilities: new Set(["user.elicit"]),
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
  });

  it("feeds back unknown tool error then succeeds (no retry consumed)", async () => {
    const { adapter } = fakeAdapter([
      {
        content: null,
        toolCalls: [{ id: "c1", name: "nonexistent", arguments: {} }],
      },
      { content: '{"summary": "done"}' },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([readTool()]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      allowedCapabilities: new Set(["user.elicit"]),
      options: { maxModelRetries: 0 },
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
  });

  it("exceeds maxToolRounds on persistent tool calls", async () => {
    const toolCall: ModelResponse = {
      content: null,
      toolCalls: [{ id: "c1", name: "read", arguments: { question: "q" } }],
    };
    const { adapter } = fakeAdapter([toolCall, toolCall, toolCall, toolCall]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([readTool()]),
      maxToolRounds: 3,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      allowedCapabilities: new Set(["user.elicit"]),
    });
    await expect(executor.execute(ctx)).rejects.toThrow(ModelOutputValidationError);
  });
});

// ---------------------------------------------------------------------------
// Numeric output validation
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — numeric output", () => {
  it("accepts number output", async () => {
    const { adapter } = fakeAdapter([{ content: '{"score": 1.5}' }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "score", type: "number" }],
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ score: 1.5 });
  });

  it("rejects bool for number output", async () => {
    const { adapter } = fakeAdapter([{ content: '{"score": true}' }, { content: '{"score": true}' }, { content: '{"score": true}' }, { content: '{"score": true}' }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "score", type: "number" }],
    });
    await expect(executor.execute(ctx)).rejects.toThrow(ModelOutputValidationError);
  });
});

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — streaming", () => {
  it("forwards delta chunks as model_delta events", async () => {
    const collected: import("../events.js").WorkflowEvent[] = [];
    const emitter = new WorkflowEventEmitter("r1", async (e) => { collected.push(e); });
    const { adapter } = fakeStreamingAdapter([
      { kind: "delta", channel: "assistant", text: "Hello " },
      { kind: "delta", channel: "assistant", text: "world" },
      { kind: "completed", response: { content: '{"summary": "done"}' } },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      emitter,
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });

    const deltas = collected.filter((e) => e.kind === "model_delta");
    expect(deltas.length).toBe(2);
    expect(deltas[0].text).toBe("Hello ");
    expect(deltas[0].channel).toBe("assistant");
    expect(deltas[1].text).toBe("world");

    const completed = collected.filter((e) => e.kind === "model_completed");
    expect(completed.length).toBe(1);
  });

  it("emits model_completed for non-streaming adapter", async () => {
    const collected: import("../events.js").WorkflowEvent[] = [];
    const emitter = new WorkflowEventEmitter("r1", async (e) => { collected.push(e); });
    const { adapter } = fakeAdapter([{ content: '{"summary": "ns"}' }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      emitter,
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "ns" });
    const deltas = collected.filter((e) => e.kind === "model_delta");
    expect(deltas.length).toBe(0);
    const completed = collected.filter((e) => e.kind === "model_completed");
    expect(completed.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Tagged envelope protocol
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — tagged envelope", () => {
  it("parses final envelope", async () => {
    const { adapter } = fakeAdapter([
      { content: JSON.stringify({ kind: "final", output: { summary: "done" } }) },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
      actionProtocol: "tagged_envelope",
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
  });

  it("parses tool_call envelope then final", async () => {
    const { adapter } = fakeAdapter([
      { content: JSON.stringify({ kind: "tool_call", tool: "read", args: { question: "hi" } }) },
      { content: JSON.stringify({ kind: "final", output: { summary: "done" } }) },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([readTool()]),
      maxToolRounds: 32,
      actionProtocol: "tagged_envelope",
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      allowedCapabilities: new Set(["user.elicit"]),
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
  });

  it("tolerates trailing prose after the envelope (small-model behavior)", async () => {
    const { adapter } = fakeAdapter([
      {
        content:
          '{"kind":"final","output":{"summary":"done"}}\n\nSorry for the confusion.',
      },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
      actionProtocol: "tagged_envelope",
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
  });
});
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — cancellation", () => {
  it("forwards RunOptions.signal into the ModelRequest", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: '{"summary": "done"}' },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
    });
    const ac = new AbortController();
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      options: { signal: ac.signal } as Record<string, unknown>,
    });
    await executor.execute(ctx);
    expect(calls[0].signal).toBe(ac.signal);
  });
});

// ---------------------------------------------------------------------------
// Tagged-envelope hardening
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — tagged-envelope hardening", () => {
  it("retries on a malformed envelope (missing kind)", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: JSON.stringify({ summary: "no envelope wrapper" }) },
      { content: JSON.stringify({ kind: "final", output: { summary: "done" } }) },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
      actionProtocol: "tagged_envelope",
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
    expect(calls.length).toBe(2);
  });

  it("extracts the envelope after thinking reasoning that quotes a JSON-like value (thinking-model behavior)", async () => {
    // A thinking model writes reasoning prose, quotes a JSON-like object
    // (here {"input.eps": 0.02}) in that prose, and only emits the real
    // tagged envelope at the very end. The extractor must skip the
    // non-envelope JSON object and return the {"kind":"final",...}.
    const content =
      "Okay, let's see. The context given is \"{\"input.eps\": 0.02}\".\n" +
      "Hmm, the baseline score must be the input value itself.\n\n" +
      "So the answer is 0.02.\n\n" +
      "Therefore, the final output should be {\"kind\":\"final\",\"output\":{\"score\":0.02}}.";
    const { adapter, calls } = fakeAdapter([
      { content },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
      actionProtocol: "tagged_envelope",
    });
    const ctx = makeCtx({
      writes: [{ name: "score", type: "number" }],
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ score: 0.02 });
    expect(calls.length).toBe(1); // no retry needed
  });

  it("auto-closes a truncated envelope missing its final '}' (streaming truncation)", async () => {
    // A streaming model stops right after the last value, dropping trailing '}'s.
    // Content: thinking prose + truncated envelope.
    const content =
      "Okay, so I guess the score is 2.\n\n" +
      '{"kind":"final","output":{"score":2}';
    const { adapter, calls } = fakeAdapter([{ content }]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([]),
      maxToolRounds: 32,
      actionProtocol: "tagged_envelope",
    });
    const ctx = makeCtx({
      writes: [{ name: "score", type: "number" }],
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ score: 2 });
    expect(calls.length).toBe(1); // no retry needed
  });

  it("includes tool descriptions in the initial prompt", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: JSON.stringify({ kind: "final", output: { summary: "done" } }) },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([readTool()]),
      maxToolRounds: 32,
      actionProtocol: "tagged_envelope",
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      allowedCapabilities: new Set(["user.elicit"]),
    });
    await executor.execute(ctx);
    const systemMsg = calls[0].messages[0] as { content: string };
    expect(systemMsg.content).toContain("elicit");
    expect(systemMsg.content).toContain("tool_call");
    expect(systemMsg.content).toContain("final");
  });

  it("feeds tool results back as user messages (not role:tool)", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: JSON.stringify({ kind: "tool_call", tool: "read", args: { question: "hi" } }) },
      { content: JSON.stringify({ kind: "final", output: { summary: "done" } }) },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([readTool()]),
      maxToolRounds: 32,
      actionProtocol: "tagged_envelope",
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      allowedCapabilities: new Set(["user.elicit"]),
      toolCallsLog: [],
    });
    await executor.execute(ctx);
    // The second request's messages should include a user-role tool result.
    const secondMessages = calls[1].messages as Array<Record<string, unknown>>;
    const toolResult = secondMessages.find(
      (m) => m.role === "user" && typeof m.content === "string" && (m.content as string).includes("returned:"),
    );
    expect(toolResult).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Tool argument validation
// ---------------------------------------------------------------------------

describe("ModelStageExecutor — argument validation", () => {
  it("rejects unknown tool arguments in native protocol", async () => {
    // The model returns a tool call with an unknown arg; the executor feeds
    // back the error and the model then produces final output.
    const { adapter } = fakeAdapter([
      {
        content: null,
        toolCalls: [{ id: "c1", name: "read", arguments: { question: "hi", bogus: 1 } }],
      },
      { content: '{"summary": "done"}' },
    ]);
    const executor = new ModelStageExecutor({
      model: adapter,
      tools: new ToolRegistry([readTool()]),
      maxToolRounds: 32,
    });
    const ctx = makeCtx({
      writes: [{ name: "summary", type: "string" }],
      allowedCapabilities: new Set(["user.elicit"]),
      options: { maxModelRetries: 0 },
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ summary: "done" });
  });
});
