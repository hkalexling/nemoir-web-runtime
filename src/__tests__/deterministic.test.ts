/**
 * Deterministic stage executor tests.
 *
 * Tests the TS port of Python's DeterministicStageExecutor: tool selection,
 * scalar result wrapping, object projection, no model events emitted,
 * policy enforcement on deterministic calls, and exec arg resolution
 * with JSON coercion for `json`-typed params.
 */

import { describe, it, expect } from "vitest";
import { DeterministicStageExecutor, selectDeterministicTool } from "../deterministic.js";
import { ToolRegistry } from "../tools.js";
import { makeStage, makeWrite } from "./helpers.js";
import type { StageSpec } from "../manifest.js";
import type { StageContext } from "../runtime.js";
import { DataUnavailableError } from "../errors.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyRegistry(): ToolRegistry {
  return new ToolRegistry([]);
}

function makeToolRegistry(tools: { name: string; capability: string; inputSchema: Record<string, string>; handler: (args: Record<string, unknown>) => Promise<unknown> }[]): ToolRegistry {
  return new ToolRegistry(
    tools.map((t) => ({
      name: t.name,
      capability: t.capability,
      description: t.name,
      inputSchema: t.inputSchema as Record<string, import("../tools.js").ToolParamType>,
      handler: async (args: Record<string, unknown>) => t.handler(args),
    })),
  );
}

function makeStageContext(opts: {
  stage: StageSpec;
  inputs?: Record<string, unknown>;
  readableContext?: Record<string, unknown>;
  callTool?: (capability: string, args: Record<string, unknown>, toolName?: string) => Promise<unknown>;
}): StageContext {
  return {
    workflowId: "test",
    stage: opts.stage,
    inputs: opts.inputs ?? {},
    readableContext: opts.readableContext ?? {},
    allowedCapabilities: opts.stage.requires,
    options: {
      maxSteps: 64,
      maxModelRetries: 3,
      maxToolRounds: 32,
      timeoutSeconds: null,
      metadata: {},
      reasoning: "none",
      signal: undefined,
    },
    callTool: opts.callTool ?? (async () => ({})),
    eventEmitter: null,
  };
}

// ---------------------------------------------------------------------------
// selectDeterministicTool
// ---------------------------------------------------------------------------

describe("selectDeterministicTool", () => {
  it("returns null when no tools registered for the capability", () => {
    const stage = makeStage("A", {
      execution: { kind: "tool", capability: "user.confirm", args: new Map([["message", { kind: "literal", type: "string", value: "ok?" }]]) },
    });
    const result = selectDeterministicTool(stage, emptyRegistry());
    expect(result).toBeNull();
  });

  it("picks the single tool when only one is registered", () => {
    const stage = makeStage("A", {
      execution: { kind: "tool", capability: "user.confirm", args: new Map([["message", { kind: "literal", type: "string", value: "ok?" }]]) },
    });
    const tools = makeToolRegistry([
      { name: "confirm", capability: "user.confirm", inputSchema: { message: "string" }, handler: async () => true },
    ]);
    expect(selectDeterministicTool(stage, tools)).toBe("confirm");
  });

  it("throws on ambiguity when multiple tools match", () => {
    const stage = makeStage("A", {
      execution: { kind: "tool", capability: "user.confirm", args: new Map([["message", { kind: "literal", type: "string", value: "ok?" }]]) },
    });
    const tools = makeToolRegistry([
      { name: "confirm_a", capability: "user.confirm", inputSchema: { message: "string" }, handler: async () => true },
      { name: "confirm_b", capability: "user.confirm", inputSchema: { message: "string" }, handler: async () => true },
    ]);
    expect(() => selectDeterministicTool(stage, tools)).toThrow("multiple tools equally satisfy");
  });
});

// ---------------------------------------------------------------------------
// DeterministicStageExecutor — execution
// ---------------------------------------------------------------------------

describe("DeterministicStageExecutor — execute", () => {
  it("resolves literal exec args and projects to writes", async () => {
    const stage = makeStage("Confirm", {
      writes: [makeWrite("ok", "bool")],
      execution: { kind: "tool", capability: "user.confirm", args: new Map([["message", { kind: "literal", type: "string", value: "Proceed?" }]]) },
      requires: new Set(["user.confirm"]),
    });
    const tools = makeToolRegistry([
      { name: "confirm", capability: "user.confirm", inputSchema: { message: "string" }, handler: async (args) => args.message === "Proceed?" },
    ]);
    const executor = new DeterministicStageExecutor({
      tools,
      toolForStage: new Map([["Confirm", "confirm"]]),
    });
    const ctx = makeStageContext({
      stage,
      callTool: async (_cap, _args, _toolName) => true,
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ ok: true });
  });

  it("wraps scalar result for single-write stages", async () => {
    const stage = makeStage("Confirm", {
      writes: [makeWrite("ok", "bool")],
      execution: { kind: "tool", capability: "user.confirm", args: new Map([["message", { kind: "literal", type: "string", value: "?" }]]) },
      requires: new Set(["user.confirm"]),
    });
    const tools = makeToolRegistry([
      { name: "confirm", capability: "user.confirm", inputSchema: { message: "string" }, handler: async () => false },
    ]);
    const executor = new DeterministicStageExecutor({
      tools,
      toolForStage: new Map([["Confirm", "confirm"]]),
    });
    const ctx = makeStageContext({
      stage,
      callTool: async (_cap, _args, _toolName) => false,
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ ok: false });
  });

  it("projects object result to declared writes", async () => {
    const stage = makeStage("Read", {
      writes: [makeWrite("found", "bool"), makeWrite("value", "string")],
      execution: { kind: "tool", capability: "browser.storage.read", args: new Map([["key", { kind: "literal", type: "string", value: "k1" }]]) },
      requires: new Set(["browser.storage.read"]),
    });
    const tools = makeToolRegistry([
      { name: "storage_read", capability: "browser.storage.read", inputSchema: { key: "string" }, handler: async () => ({ key: "k1", found: true, value: "v1" }) },
    ]);
    const executor = new DeterministicStageExecutor({
      tools,
      toolForStage: new Map([["Read", "storage_read"]]),
    });
    const ctx = makeStageContext({
      stage,
      callTool: async (_cap, _args, _toolName) => ({ key: "k1", found: true, value: "v1" }),
    });
    const result = await executor.execute(ctx);
    // Only declared writes are projected
    expect(result).toEqual({ found: true, value: "v1" });
  });

  it("projects the declared write name from a sandbox-style result envelope", async () => {
    // Dynamic code returning `{ result: { doubled: 42 } }` must populate a
    // stage writing `result: json` — the envelope contract documented in
    // docs/web-backend.md §9 / docs/dsl-and-ir.md.
    const stage = makeStage("RunSandbox", {
      writes: [makeWrite("result", "json")],
      execution: {
        kind: "tool",
        capability: "browser.js.sandbox",
        args: new Map([
          ["code", { kind: "ref", ref: { kind: "input", name: "code" } }],
          ["input", { kind: "literal", type: "json", value: { x: 21 } }],
        ]),
      },
      requires: new Set(["browser.js.sandbox"]),
    });
    const executor = new DeterministicStageExecutor({
      tools: emptyRegistry(),
      toolForStage: new Map([["RunSandbox", "js_sandbox"]]) });
    const ctx = makeStageContext({
      stage,
      inputs: { code: "return { result: { doubled: input.x * 2 } };" },
      callTool: async () => ({ result: { doubled: 42 } }),
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ result: { doubled: 42 } });
  });

  it("throws when no tool is selected for a stage", async () => {
    const stage = makeStage("Confirm", {
      execution: { kind: "tool", capability: "user.confirm", args: new Map() },
      requires: new Set(["user.confirm"]),
    });
    const tools = makeToolRegistry([
      { name: "confirm", capability: "user.confirm", inputSchema: { message: "string" }, handler: async () => true },
    ]);
    const executor = new DeterministicStageExecutor({
      tools,
      toolForStage: new Map(), // no selection
    });
    const ctx = makeStageContext({ stage });
    await expect(executor.execute(ctx)).rejects.toThrow(DataUnavailableError);
  });

  it("passes a native json literal through to a json-typed param", async () => {
    // Medium #2: the DSL lowers structured JSON literals natively (grammar
    // `json_value`), so the runtime receives the parsed object directly —
    // no string coercion. The storage_write tool receives the object as-is.
    const stage = makeStage("Write", {
      writes: [makeWrite("written", "bool")],
      execution: { kind: "tool", capability: "browser.storage.write", args: new Map([
        ["key", { kind: "literal", type: "string", value: "k" }],
        ["value", { kind: "literal", type: "json", value: { n: 42 } }],
      ]) },
      requires: new Set(["browser.storage.write"]),
    });
    const tools = makeToolRegistry([
      { name: "storage_write", capability: "browser.storage.write", inputSchema: { key: "string", value: "json" }, handler: async (args) => {
        // value should be the structured object, not a string
        expect(args.value).toEqual({ n: 42 });
        expect(typeof args.value).toBe("object");
        return { key: "k", written: true };
      }},
    ]);
    const executor = new DeterministicStageExecutor({
      tools,
      toolForStage: new Map([["Write", "storage_write"]]),
    });
    const ctx = makeStageContext({
      stage,
      callTool: async (_cap, _args, _toolName) => ({ key: "k", written: true }),
    });
    const result = await executor.execute(ctx);
    expect(result).toEqual({ written: true });
  });

  it("throws when a string is passed to a json-typed param (fail-closed)", async () => {
    // Medium #2: a hand-authored manifest tunneling JSON through a string
    // literal is rejected fail-closed rather than silently JSON.parse-ed.
    const stage = makeStage("Write", {
      writes: [makeWrite("written", "bool")],
      execution: { kind: "tool", capability: "browser.storage.write", args: new Map([
        ["key", { kind: "literal", type: "string", value: "k" }],
        ["value", { kind: "literal", type: "string", value: "{\"n\":42}" }],
      ]) },
      requires: new Set(["browser.storage.write"]),
    });
    const tools = makeToolRegistry([
      { name: "storage_write", capability: "browser.storage.write", inputSchema: { key: "string", value: "json" }, handler: async () => ({}) },
    ]);
    const executor = new DeterministicStageExecutor({
      tools,
      toolForStage: new Map([["Write", "storage_write"]]),
    });
    const ctx = makeStageContext({ stage });
    await expect(executor.execute(ctx)).rejects.toThrow(/json.*string|JSON literal/i);
  });

  it("routes through callTool (policy enforcement)", async () => {
    const stage = makeStage("Confirm", {
      writes: [makeWrite("ok", "bool")],
      execution: { kind: "tool", capability: "user.confirm", args: new Map([["message", { kind: "literal", type: "string", value: "P?" }]]) },
      requires: new Set(["user.confirm"]),
    });
    const tools = makeToolRegistry([
      { name: "confirm", capability: "user.confirm", inputSchema: { message: "string" }, handler: async () => true },
    ]);
    const executor = new DeterministicStageExecutor({
      tools,
      toolForStage: new Map([["Confirm", "confirm"]]),
    });
    let callToolReceived = false;
    const ctx = makeStageContext({
      stage,
      callTool: async (cap, args, toolName) => {
        callToolReceived = true;
        expect(cap).toBe("user.confirm");
        expect(args).toEqual({ message: "P?" });
        expect(toolName).toBe("confirm");
        return true;
      },
    });
    await executor.execute(ctx);
    expect(callToolReceived).toBe(true);
  });
});
