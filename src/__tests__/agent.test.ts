/**
 * Agent integration tests.
 *
 * Tests the WorkflowAgent factory end-to-end against a web-compatible
 * workflow using a fake model adapter and a fake UI host.
 */

import { describe, it, expect } from "vitest";
import { WorkflowAgent } from "../agent.js";
import { fakeAdapter } from "./helpers.js";
import type { WebUiHost } from "../ui-host.js";

// A minimal web-compatible IR: two model stages, one input, string output.
const simpleIr = {
  ir_version: "0.1",
  kind: "workflow_ir",
  source: { frontend: "test", file: "test.nemo" },
  workflow: {
    id: "SimpleWorkflow",
    entry: "First",
    exits: ["Second"],
    transition_semantics: {
      selection: "first_match_by_priority",
      no_match: "error_unless_exit",
    },
  },
  inputs: [{ id: "task", type: "string" }],
  capabilities: [],
  policies: [],
  nodes: [
    {
      id: "First",
      annotations: ["entry"],
      prompt: "Process the first stage.",
      reads: [{ ref: { kind: "input", name: "task" }, optional: false, origin: "implicit_entry_input" }],
      writes: [{ name: "summary", type: "string", optional: false }],
      requires: [],
      transitions: [{ to: "Second", priority: 0, reason: "fallthrough", guard: { kind: "always" } }],
    },
    {
      id: "Second",
      annotations: ["exit"],
      prompt: "Summarize.",
      reads: [],
      writes: [{ name: "result", type: "string", optional: false }],
      requires: [],
      transitions: [],
    },
  ],
};

// A web-compatible IR with user.confirm capability + before policy.
const uiIr = {
  ir_version: "0.1",
  kind: "workflow_ir",
  source: { frontend: "test", file: "test.nemo" },
  workflow: {
    id: "UiWorkflow",
    entry: "Ask",
    exits: ["Done"],
    transition_semantics: {
      selection: "first_match_by_priority",
      no_match: "error_unless_exit",
    },
  },
  inputs: [{ id: "task", type: "string" }],
  capabilities: ["user.confirm"],
  policies: [
    {
      id: "before user.elicit(question) requires user.confirm",
      kind: "before",
      trigger: {
        capability: "user.elicit",
        bind: { question: { kind: "arg", name: "question" } },
      },
      requires: [{ capability: "user.confirm" }],
    },
  ],
  nodes: [
    {
      id: "Ask",
      annotations: ["entry"],
      prompt: "Ask the user something.",
      reads: [{ ref: { kind: "input", name: "task" }, optional: false, origin: "implicit_entry_input" }],
      writes: [{ name: "answer", type: "string", optional: false }],
      requires: [{ capability: "user.elicit" }],
      transitions: [{ to: "Done", priority: 0, reason: "fallthrough", guard: { kind: "always" } }],
    },
    {
      id: "Done",
      annotations: ["exit"],
      prompt: "Return the result.",
      reads: [{ ref: { kind: "node_output", node: "Ask", field: "answer" }, optional: false, origin: "dsl_stage_input" }],
      writes: [{ name: "result", type: "string", optional: false }],
      requires: [],
      transitions: [],
    },
  ],
};

const fakeUiHost: WebUiHost = {
  async elicit(question: string): Promise<string> {
    return `answer to: ${question}`;
  },
  async confirm(): Promise<boolean> {
    return true;
  },
};

describe("WorkflowAgent — basic run", () => {
  it("runs a simple model-only workflow end-to-end", async () => {
    const { adapter } = fakeAdapter([
      { content: '{"summary": "first stage done"}' },
      { content: '{"result": "final result"}' },
    ]);

    const agent = new WorkflowAgent(simpleIr, { modelAdapter: adapter });

    const result = await agent.run({ task: "hello" });
    expect(result.output).toEqual({ result: "final result" });
  });

  it("streams events", async () => {
    const { adapter } = fakeAdapter([
      { content: '{"summary": "first"}' },
      { content: '{"result": "done"}' },
    ]);

    const agent = new WorkflowAgent(simpleIr, { modelAdapter: adapter });

    const events: import("../events.js").WorkflowEvent[] = [];
    for await (const event of agent.stream({ task: "hello" })) {
      events.push(event);
    }

    expect(events[0].kind).toBe("run_started");
    expect(events[events.length - 1].kind).toBe("run_completed");
  });
});

describe("WorkflowAgent — UI host", () => {
  it("runs a workflow with user.confirm before-policy", async () => {
    // The Ask stage requires user.elicit. The before-policy runs user.confirm
    // first. But the model executor calls the stage's allowed capability
    // (user.elicit) via tool_call, which triggers the before-policy.
    // For this test, the model returns content-only (no tool calls),
    // so the before-policy never fires — the stage just produces "answer".
    const { adapter } = fakeAdapter([
      { content: '{"answer": "my answer"}' },
      { content: '{"result": "final"}' },
    ]);

    const agent = new WorkflowAgent(uiIr, {
      modelAdapter: adapter,
      uiHost: fakeUiHost,
    });

    const result = await agent.run({ task: "test" });
    expect(result.output).toEqual({ result: "final" });
  });

  it("throws if uiHost is missing for user.confirm capability", () => {
    const { adapter } = fakeAdapter([]);

    expect(() => new WorkflowAgent(uiIr, {
      modelAdapter: adapter,
      // no uiHost
    })).toThrow();
  });
});

describe("WorkflowAgent — error handling", () => {
  it("throws if no model adapter is provided for model-stage workflow", () => {
    expect(() => new WorkflowAgent(simpleIr, {} as never)).toThrow("modelAdapter");
  });

  it("constructs a deterministic-only workflow without modelAdapter", () => {
    // A minimal IR with all deterministic tool stages (no model stages)
    const detIr = {
      ir_version: "0.1",
      kind: "workflow_ir",
      source: { frontend: "test", file: "test.nemo" },
      workflow: {
        id: "DetOnly",
        entry: "Confirm",
        exits: ["Confirm"],
        transition_semantics: { selection: "first_match_by_priority", no_match: "error_unless_exit" },
      },
      inputs: [],
      capabilities: ["user.confirm"],
      policies: [],
      nodes: [{
        id: "Confirm",
        annotations: ["entry", "exit"],
        prompt: "",
        reads: [],
        writes: [{ name: "ok", type: "bool", optional: false }],
        requires: [{ capability: "user.confirm" }],
        transitions: [],
        execution: { kind: "tool", capability: "user.confirm", args: { message: { kind: "literal", type: "string", value: "Proceed?" } } },
      }],
    };
    const agent = new WorkflowAgent(detIr, {
      uiHost: {
        async elicit() { return ""; },
        async confirm() { return true; },
      },
    });
    expect(agent.workflowId).toBe("DetOnly");
  });

  it("runs a deterministic-only workflow end-to-end without a model adapter", async () => {
    // Medium #3: the prior test only *constructed* the agent; this one
    // exercises the deterministic dispatch path (resolve args → callTool →
    // output validation) and asserts the typed result.
    const detIr = {
      ir_version: "0.1",
      kind: "workflow_ir",
      source: { frontend: "test", file: "test.nemo" },
      workflow: {
        id: "DetRun",
        entry: "Confirm",
        exits: ["Confirm"],
        transition_semantics: { selection: "first_match_by_priority", no_match: "error_unless_exit" },
      },
      inputs: [],
      capabilities: ["user.confirm"],
      policies: [],
      nodes: [{
        id: "Confirm",
        annotations: ["entry", "exit"],
        prompt: "",
        reads: [],
        writes: [{ name: "ok", type: "bool", optional: false }],
        requires: [{ capability: "user.confirm" }],
        transitions: [],
        execution: { kind: "tool", capability: "user.confirm", args: { message: { kind: "literal", type: "string", value: "Proceed?" } } },
      }],
    };
    const agent = new WorkflowAgent(detIr, {
      uiHost: {
        async elicit() { return ""; },
        async confirm() { return true; },
      },
    });
    const result = await agent.run({});
    expect(result.output).toEqual({ ok: true });
  });

  it("runs a mixed deterministic-then-model workflow", async () => {
    // Medium #3: a workflow with a deterministic user.confirm stage feeding a
    // model stage. Confirms both executors cooperate and the typed output is
    // produced from the model stage.
    const mixedIr = {
      ir_version: "0.1",
      kind: "workflow_ir",
      source: { frontend: "test", file: "test.nemo" },
      workflow: {
        id: "Mixed",
        entry: "Confirm",
        exits: ["Done"],
        transition_semantics: { selection: "first_match_by_priority", no_match: "error_unless_exit" },
      },
      inputs: [],
      capabilities: ["user.confirm"],
      policies: [],
      nodes: [
        {
          id: "Confirm",
          annotations: ["entry"],
          prompt: "",
          reads: [],
          writes: [{ name: "ok", type: "bool", optional: false }],
          requires: [{ capability: "user.confirm" }],
          transitions: [{ to: "Done", priority: 0, reason: "fallthrough", guard: { kind: "always" } }],
          execution: { kind: "tool", capability: "user.confirm", args: { message: { kind: "literal", type: "string", value: "Proceed?" } } },
        },
        {
          id: "Done",
          annotations: ["exit"],
          prompt: "Summarize.",
          reads: [{ ref: { kind: "node_output", node: "Confirm", field: "ok" }, optional: false, origin: "dsl_stage_input" }],
          writes: [{ name: "summary", type: "string", optional: false }],
          requires: [],
          transitions: [],
        },
      ],
    };
    const { adapter } = fakeAdapter([
      { content: '{"summary": "confirmed & summarized"}' },
    ]);
    const agent = new WorkflowAgent(mixedIr, {
      modelAdapter: adapter,
      actionProtocol: "native",
      uiHost: {
        async elicit() { return ""; },
        async confirm() { return true; },
      },
    });
    const result = await agent.run({});
    expect(result.output).toEqual({ summary: "confirmed & summarized" });
  });

  it("throws on path types in the IR", () => {
    const ir = JSON.parse(JSON.stringify(simpleIr));
    ir.inputs[0].type = "path";
    const { adapter } = fakeAdapter([]);

    expect(() => new WorkflowAgent(ir, { modelAdapter: adapter })).toThrow("not compatible");
  });

  it("throws on fs.read capability in the IR", () => {
    const ir = JSON.parse(JSON.stringify(simpleIr));
    ir.capabilities = ["fs.read"];
    const { adapter } = fakeAdapter([]);

    expect(() => new WorkflowAgent(ir, { modelAdapter: adapter })).toThrow("not compatible");
  });
});

describe("WorkflowAgent — actionProtocol", () => {
  it("defaults to native protocol", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: '{"summary": "first stage done"}' },
      { content: '{"result": "final result"}' },
    ]);
    const agent = new WorkflowAgent(simpleIr, { modelAdapter: adapter });
    await agent.run({ task: "hello" });
    // Native protocol: system prompt does NOT mention the tagged envelope.
    const systemMsg = calls[0].messages[0] as { content: string };
    expect(systemMsg.content).not.toContain("tagged envelope");
  });

  it("threads tagged_envelope through to the executor", async () => {
    const { adapter, calls } = fakeAdapter([
      { content: JSON.stringify({ kind: "final", output: { summary: "first" } }) },
      { content: JSON.stringify({ kind: "final", output: { result: "done" } }) },
    ]);
    const agent = new WorkflowAgent(simpleIr, {
      modelAdapter: adapter,
      actionProtocol: "tagged_envelope",
    });
    const result = await agent.run({ task: "hello" });
    expect(result.output).toEqual({ result: "done" });
    const systemMsg = calls[0].messages[0] as { content: string };
    expect(systemMsg.content).toContain("tagged JSON envelope");
  });
});
