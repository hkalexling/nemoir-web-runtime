/**
 * IR decoder tests.
 *
 * Decodes the real `judge_candidate` workflow JSON (the canonical
 * web-compatible positive fixture) and asserts structural correctness.
 * Also tests web-target defensiveness (path/fs/os.shell rejection).
 */

import { describe, it, expect } from "vitest";
import { decodeWorkflowIr, validateForWeb } from "../ir.js";
import { buildWorkflowManifest } from "../manifest.js";

// The canonical web-compatible IR, embedded from the Rust fixture.
// This mirrors the JSON that `nemo compile --target web` emits.
import judgeCandidateIr from "./judge-candidate-ir.json" with { type: "json" };

describe("decodeWorkflowIr", () => {
  it("decodes judge_candidate IR without errors", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    expect(ir.ir_version).toBe("0.1");
    expect(ir.kind).toBe("workflow_ir");
    expect(ir.workflow.id).toBe("JudgeCandidate");
    expect(ir.workflow.entry).toBe("Baseline");
    expect(ir.workflow.exits).toEqual(["Accept", "Confirm", "Reject"]);
  });

  it("defaults omitted execution to model", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    // judge_candidate has no explicit execution fields (all model stages).
    // The decoder should default them to { kind: "model" }.
    for (const node of ir.nodes) {
      expect(node.execution.kind).toBe("model");
    }
  });

  it("preserves reads and transitions", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    const judgeStage = ir.nodes.find((n) => n.id === "JudgeCandidate")!;
    expect(judgeStage.reads.length).toBe(2);
    expect(judgeStage.transitions.length).toBe(3);
    // The first transition uses a compare/binop guard
    const firstTrans = judgeStage.transitions[0];
    expect(firstTrans.guard.kind).toBe("if");
  });

  it("builds a runtime manifest from decoded IR", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    const manifest = buildWorkflowManifest(ir);
    expect(manifest.workflowId).toBe("JudgeCandidate");
    expect(manifest.entryStageId).toBe("Baseline");
    expect(manifest.exitStageIds.size).toBe(3);
    expect(manifest.stages.length).toBe(6);
    // All stages should be model-only
    for (const stage of manifest.stages) {
      expect(stage.execution.kind).toBe("model");
    }
  });
});

describe("validateForWeb", () => {
  it("passes for judge_candidate", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    // decodeWorkflowIr already runs validateForWeb, but test explicitly
    const issues = validateForWeb(ir);
    expect(issues).toEqual([]);
  });

  it("rejects path input types", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.inputs[0].type = "path";
    const issues = validateForWeb(ir);
    expect(issues.length).toBe(1);
    expect(issues[0].message).toContain("path");
  });

  it("rejects fs.read capability", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.capabilities.push("fs.read");
    const issues = validateForWeb(ir);
    expect(issues.some((i) => i.message.includes("fs.read"))).toBe(true);
  });

  it("rejects os.shell capability", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.capabilities.push("os.shell");
    const issues = validateForWeb(ir);
    expect(issues.some((i) => i.message.includes("os.shell"))).toBe(true);
  });

  it("allows deterministic user.confirm stages on web", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.nodes[0].execution = { kind: "tool", capability: "user.confirm" };
    const issues = validateForWeb(ir);
    // user.confirm is web-allowed, so deterministic stage should pass
    expect(issues.filter((i) => i.path.includes("execution")).length).toBe(0);
  });

  it("rejects deterministic tool stages with unsupported capabilities", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.nodes[0].execution = { kind: "tool", capability: "fs.read" };
    const issues = validateForWeb(ir);
    expect(issues.some((i) => i.message.includes("fs.read"))).toBe(true);
  });

  it("allows user.elicit and user.confirm", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.capabilities.push("user.elicit", "user.confirm");
    const issues = validateForWeb(ir);
    expect(issues).toEqual([]);
  });

  it("allows dynamic sandbox source only with explicit confirmation policy", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.inputs.push({ id: "user_code", type: "string" });
    ir.capabilities.push("browser.js.sandbox", "user.confirm");
    ir.nodes[0].requires.push({ capability: "browser.js.sandbox" });
    ir.nodes[0].execution = {
      kind: "tool",
      capability: "browser.js.sandbox",
      args: {
        code: { kind: "ref", ref: { kind: "input", name: "user_code" } },
        input: { kind: "literal", type: "json", value: {} },
      },
    };
    ir.policies.push({
      id: "before browser.js.sandbox(code) requires user.confirm",
      kind: "before",
      trigger: {
        capability: "browser.js.sandbox",
        bind: { code: { kind: "arg", name: "code" } },
      },
      requires: [{ capability: "user.confirm", args: {} }],
    });

    expect(validateForWeb(ir)).toEqual([]);
  });

  it("rejects dynamic sandbox without explicit confirmation policy", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.capabilities.push("browser.js.sandbox");
    ir.nodes[0].requires.push({ capability: "browser.js.sandbox" });
    ir.nodes[0].execution = {
      kind: "tool",
      capability: "browser.js.sandbox",
      args: {
        code: { kind: "literal", type: "string", value: "return { ok: true };" },
        input: { kind: "literal", type: "json", value: {} },
      },
    };

    const issues = validateForWeb(ir);
    expect(issues.some((i) => i.message.includes("explicit approval policy"))).toBe(true);
  });

  it("rejects browser.js.sandbox in a model stage", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.capabilities.push("browser.js.sandbox");
    ir.nodes[0].requires.push({ capability: "browser.js.sandbox" });

    const issues = validateForWeb(ir);
    expect(issues.some((i) => i.message.includes("only allowed in deterministic"))).toBe(true);
  });

  it("rejects browser.js.sandbox code ref to a json input", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.inputs.push({ id: "user_code", type: "json" });
    ir.capabilities.push("browser.js.sandbox", "user.confirm");
    ir.nodes[0].requires.push({ capability: "browser.js.sandbox" });
    ir.nodes[0].execution = {
      kind: "tool",
      capability: "browser.js.sandbox",
      args: {
        code: { kind: "ref", ref: { kind: "input", name: "user_code" } },
        input: { kind: "literal", type: "json", value: {} },
      },
    };
    ir.policies.push({
      id: "before browser.js.sandbox(code) requires user.confirm",
      kind: "before",
      trigger: {
        capability: "browser.js.sandbox",
        bind: { code: { kind: "arg", name: "code" } },
      },
      requires: [{ capability: "user.confirm", args: {} }],
    });

    const issues = validateForWeb(ir);
    expect(issues.some((i) => i.message.includes("non-optional string"))).toBe(true);
  });

  it("rejects browser.js.sandbox code ref to a json node-output write", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.capabilities.push("browser.js.sandbox", "user.confirm");
    // Give the first node a json-typed `code` write it can reference.
    ir.nodes[0].writes = [{ name: "code", type: "json", optional: false }];
    ir.nodes[0].requires.push({ capability: "browser.js.sandbox" });
    ir.nodes[0].execution = {
      kind: "tool",
      capability: "browser.js.sandbox",
      args: {
        code: { kind: "ref", ref: { kind: "node_output", node: ir.nodes[0].id, field: "code" } },
        input: { kind: "literal", type: "json", value: {} },
      },
    };
    ir.policies.push({
      id: "before browser.js.sandbox(code) requires user.confirm",
      kind: "before",
      trigger: {
        capability: "browser.js.sandbox",
        bind: { code: { kind: "arg", name: "code" } },
      },
      requires: [{ capability: "user.confirm", args: {} }],
    });

    const issues = validateForWeb(ir);
    expect(issues.some((i) => i.message.includes("non-optional string"))).toBe(true);
  });

  it("rejects browser.js.sandbox code ref to an optional string node-output write", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.capabilities.push("browser.js.sandbox", "user.confirm");
    ir.nodes[0].writes = [{ name: "code", type: "string", optional: true }];
    ir.nodes[0].requires.push({ capability: "browser.js.sandbox" });
    ir.nodes[0].execution = {
      kind: "tool",
      capability: "browser.js.sandbox",
      args: {
        code: { kind: "ref", ref: { kind: "node_output", node: ir.nodes[0].id, field: "code" } },
        input: { kind: "literal", type: "json", value: {} },
      },
    };
    ir.policies.push({
      id: "before browser.js.sandbox(code) requires user.confirm",
      kind: "before",
      trigger: {
        capability: "browser.js.sandbox",
        bind: { code: { kind: "arg", name: "code" } },
      },
      requires: [{ capability: "user.confirm", args: {} }],
    });

    const issues = validateForWeb(ir);
    expect(issues.some((i) => i.message.includes("non-optional string"))).toBe(true);
  });
});

describe("decodeWorkflowIr error handling", () => {
  it("throws on invalid JSON structure", () => {
    expect(() => decodeWorkflowIr({ not: "valid" })).toThrow();
  });

  it("throws on path types", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.inputs[0].type = "path";
    expect(() => decodeWorkflowIr(ir)).toThrow("not compatible with the web target");
  });

  it("throws on fs.read capability", () => {
    const ir = decodeWorkflowIr(judgeCandidateIr);
    ir.capabilities.push("fs.read");
    expect(() => decodeWorkflowIr(ir)).toThrow("not compatible with the web target");
  });
});
