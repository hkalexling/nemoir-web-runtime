/**
 * Runtime state-machine tests.
 *
 * Ports the web-safe subset of `python/nemoir-runtime/tests/test_runtime.py`
 * and `test_numeric_transitions.py`: transitions by priority, guard
 * evaluation (always/has_value/missing/eq/if), numeric compare/binop with
 * null propagation, output validation, max_steps, optional-array
 * normalization.
 */

import { describe, it, expect } from "vitest";
import { WorkflowRuntime } from "../runtime.js";
import { ToolRegistry } from "../tools.js";
import {
  scriptedExecutor,
  makeManifest,
  makeStage,
  makeWrite,
  makeRead,
  makeTransition,
  makeInput,
  ref,
  expr,
  guard,
} from "./helpers.js";
import type { StageSpec } from "../manifest.js";
import {
  NoTransitionMatchedError,
  MaxStepsExceededError,
  StageOutputValidationError,
  DataUnavailableError,
  WorkflowValidationError,
  PolicyEvaluationError,
} from "../errors.js";

function emptyRegistry(): ToolRegistry {
  return new ToolRegistry([]);
}

// ---------------------------------------------------------------------------
// Entry / exit tests
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — entry/exit", () => {
  it("starts at entry stage and runs to exit", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("out_a", "string")],
        transitions: [makeTransition("B", 0, "fallthrough", guard.always())],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages);
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({
        A: [{ out_a: "hello" }],
        B: [{ out_b: "done" }],
      }),
    });

    const result = await runtime.run({ task: "test" });
    expect(result.output).toEqual({ out_b: "done" });
    expect(result.state.currentStageId).toBe("B");
    expect(result.state.steps).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Transition tests
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — transitions", () => {
  it("selects first matching transition by priority", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("flag", "bool")],
        transitions: [
          makeTransition("C", 0, "low", guard.always()),
          makeTransition("B", 1, "high", guard.always()),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
      makeStage("C", { writes: [makeWrite("out_c", "string")] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["B", "C"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({
        A: [{ flag: true }],
        C: [{ out_c: "c" }],
      }),
    });
    const result = await runtime.run({ task: "test" });
    // Priority 0 wins → A → C
    expect(result.output).toEqual({ out_c: "c" });
  });

  it("has_value guard matches when value is present", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("opt", "string", true)],
        transitions: [
          makeTransition("B", 0, "has_value", guard.hasValue(ref.nodeOutput("A", "opt"))),
          makeTransition("C", 1, "missing", guard.missing(ref.nodeOutput("A", "opt"))),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
      makeStage("C", { writes: [makeWrite("out_c", "string")] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["B", "C"]) });

    // opt present → has_value matches → B
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ opt: "yes" }], B: [{ out_b: "b" }] }),
    });
    const result = await runtime.run({ task: "test" });
    expect(result.output).toEqual({ out_b: "b" });
  });

  it("missing guard matches when value is null", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("opt", "string", true)],
        transitions: [
          makeTransition("B", 0, "has_value", guard.hasValue(ref.nodeOutput("A", "opt"))),
          makeTransition("C", 1, "missing", guard.missing(ref.nodeOutput("A", "opt"))),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
      makeStage("C", { writes: [makeWrite("out_c", "string")] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["B", "C"]) });

    // opt absent → missing matches → C
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{}], C: [{ out_c: "c" }] }),
    });
    const result = await runtime.run({ task: "test" });
    expect(result.output).toEqual({ out_c: "c" });
  });

  it("eq guard matches on bool true", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("ok", "bool")],
        transitions: [
          makeTransition("B", 0, "true", guard.eq(
            expr.ref(ref.nodeOutput("A", "ok")),
            expr.literal("bool", true),
          )),
          makeTransition("C", 1, "false", guard.eq(
            expr.ref(ref.nodeOutput("A", "ok")),
            expr.literal("bool", false),
          )),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
      makeStage("C", { writes: [makeWrite("out_c", "string")] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["B", "C"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ ok: true }], B: [{ out_b: "b" }] }),
    });
    const result = await runtime.run({ task: "test" });
    expect(result.output).toEqual({ out_b: "b" });
  });

  it("throws NoTransitionMatchedError when no guard matches", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("x", "string")],
        transitions: [
          makeTransition("B", 0, "never", guard.eq(
            expr.literal("bool", false),
            expr.literal("bool", true),
          )),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["B"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ x: "a" }] }),
    });
    await expect(runtime.run({ task: "test" })).rejects.toThrow(NoTransitionMatchedError);
  });
});

// ---------------------------------------------------------------------------
// Numeric guard tests (compare/binop)
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — numeric guards", () => {
  it("compare gt matches when value is greater", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("score", "number")],
        transitions: [
          makeTransition("B", 0, "gt", guard.if(
            expr.compare("gt", expr.ref(ref.nodeOutput("A", "score")), expr.literal("number", 5)),
          )),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { inputs: [makeInput("eps", "number")] });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ score: 10 }], B: [{ out_b: "done" }] }),
    });
    const result = await runtime.run({ eps: 0.05 });
    expect(result.output).toEqual({ out_b: "done" });
  });

  it("compare fails when value is below → NoTransitionMatchedError", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("score", "number")],
        transitions: [
          makeTransition("B", 0, "gt", guard.if(
            expr.compare("gt", expr.ref(ref.nodeOutput("A", "score")), expr.literal("number", 5)),
          )),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { inputs: [makeInput("eps", "number")] });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ score: 3 }] }),
    });
    await expect(runtime.run({ eps: 0.05 })).rejects.toThrow();
  });

  it("binop sub + compare gt: score - 3 > eps → true", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("score", "number")],
        transitions: [
          makeTransition("B", 0, "sub_gt", guard.if(
            expr.compare("gt",
              expr.binop("sub", expr.ref(ref.nodeOutput("A", "score")), expr.literal("number", 3)),
              expr.ref(ref.input("eps")),
            ),
          )),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { inputs: [makeInput("eps", "number")] });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ score: 10 }], B: [{ out_b: "done" }] }),
    });
    // 10 - 3 = 7 > 0.05 → true
    const result = await runtime.run({ eps: 0.05 });
    expect(result.output).toEqual({ out_b: "done" });
  });

  it("compare with null operand returns false (fail-closed)", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("score", "number", true)],
        transitions: [
          makeTransition("B", 0, "gt", guard.if(
            expr.compare("gt", expr.ref(ref.nodeOutput("A", "score")), expr.literal("number", 0)),
          )),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { inputs: [makeInput("eps", "number")] });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ score: null }] }),
    });
    // null score → compare returns false → no match → error
    await expect(runtime.run({ eps: 0.05 })).rejects.toThrow();
  });

  it("binop with null operand returns null → compare false", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("score", "number", true)],
        transitions: [
          makeTransition("B", 0, "gt", guard.if(
            expr.compare("gt",
              expr.binop("sub", expr.ref(ref.nodeOutput("A", "score")), expr.literal("number", 0.5)),
              expr.literal("number", 0),
            ),
          )),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { inputs: [makeInput("eps", "number")] });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ score: null }] }),
    });
    await expect(runtime.run({ eps: 0.05 })).rejects.toThrow();
  });

  it("div by zero raises PolicyEvaluationError", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("score", "number")],
        transitions: [
          makeTransition("B", 0, "div", guard.if(
            expr.compare("gt",
              expr.binop("div", expr.ref(ref.nodeOutput("A", "score")), expr.literal("number", 0)),
              expr.literal("number", 0),
            ),
          )),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { inputs: [makeInput("eps", "number")] });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ score: 10 }] }),
    });
    await expect(runtime.run({ eps: 0.05 })).rejects.toThrow(PolicyEvaluationError);
  });

  it("bool rejected for number write", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("score", "number")],
        transitions: [makeTransition("B", 0, "always", guard.always())],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { inputs: [makeInput("eps", "number")] });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ score: true }] }),
    });
    await expect(runtime.run({ eps: 0.05 })).rejects.toThrow(StageOutputValidationError);
  });
});

// ---------------------------------------------------------------------------
// Output validation tests
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — output validation", () => {
  it("throws on missing required output", async () => {
    const stages: StageSpec[] = [
      makeStage("A", { writes: [makeWrite("out", "string")], transitions: [] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["A"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{}] }),
    });
    await expect(runtime.run({ task: "test" })).rejects.toThrow(StageOutputValidationError);
  });

  it("throws on unknown output field", async () => {
    const stages: StageSpec[] = [
      makeStage("A", { writes: [], transitions: [] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["A"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ surprise: 1 }] }),
    });
    await expect(runtime.run({ task: "test" })).rejects.toThrow(StageOutputValidationError);
  });

  it("throws on wrong output type", async () => {
    const stages: StageSpec[] = [
      makeStage("A", { writes: [makeWrite("val", "bool")], transitions: [] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["A"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ val: "not-a-bool" }] }),
    });
    await expect(runtime.run({ task: "test" })).rejects.toThrow(StageOutputValidationError);
  });
});

// ---------------------------------------------------------------------------
// Max steps
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — max steps", () => {
  it("throws MaxStepsExceededError on infinite loop", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("x", "string")],
        transitions: [makeTransition("A", 0, "loop", guard.always())],
      }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set() });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: Array(10).fill({ x: "a" }) }),
    });
    await expect(runtime.run({ task: "test" }, { options: { maxSteps: 5 } }))
      .rejects.toThrow(MaxStepsExceededError);
  });
});

// ---------------------------------------------------------------------------
// Optional empty array normalization
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — optional array normalization", () => {
  it("normalizes empty optional arrays to null", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("opt", "string[]", true)],
        transitions: [
          makeTransition("B", 0, "has_value", guard.hasValue(ref.nodeOutput("A", "opt"))),
          makeTransition("C", 1, "missing", guard.missing(ref.nodeOutput("A", "opt"))),
        ],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
      makeStage("C", { writes: [makeWrite("out_c", "string")] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["B", "C"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ opt: [] }], C: [{ out_c: "c" }] }),
    });
    // Empty array → normalized to null → has_value false → missing true → C
    const result = await runtime.run({ task: "test" });
    expect(result.output).toEqual({ out_c: "c" });
  });
});

// ---------------------------------------------------------------------------
// Read resolution
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — read resolution", () => {
  it("throws DataUnavailableError on missing required read", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        reads: [makeRead(ref.input("nonexistent"), false)],
        writes: [],
        transitions: [],
      }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["A"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({}),
    });
    await expect(runtime.run({ task: "test" })).rejects.toThrow(DataUnavailableError);
  });
});

// ---------------------------------------------------------------------------
// Manifest validation
// ---------------------------------------------------------------------------

describe("WorkflowRuntime constructor — validation", () => {
  it("throws on duplicate stage ids", () => {
    const stages = [makeStage("A"), makeStage("A")];
    const manifest = makeManifest(stages, { exitIds: new Set(["A"]) });
    expect(() => new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({}),
    })).toThrow(WorkflowValidationError);
  });

  it("throws on missing entry stage", () => {
    const stages = [makeStage("A")];
    const manifest = makeManifest(stages, { entryId: "Bogus", exitIds: new Set(["A"]) });
    expect(() => new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({}),
    })).toThrow(WorkflowValidationError);
  });

  it("throws on missing exit stage", () => {
    const stages = [makeStage("A")];
    const manifest = makeManifest(stages, { exitIds: new Set(["Bogus"]) });
    expect(() => new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({}),
    })).toThrow(WorkflowValidationError);
  });
});

// ---------------------------------------------------------------------------
// Re-execution clears stale optional outputs
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — re-execution clears stale outputs", () => {
  it("clears stale optional outputs on stage re-entry", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("opt", "string", true)],
        transitions: [
          makeTransition("B", 0, "go_B", guard.always()),
        ],
      }),
      makeStage("B", {
        reads: [makeRead(ref.nodeOutput("A", "opt"), true)],
        writes: [makeWrite("out_b", "string")],
        transitions: [
          makeTransition("A", 0, "loop_has_value", guard.hasValue(ref.nodeOutput("A", "opt"))),
          makeTransition("C", 1, "exit_missing", guard.missing(ref.nodeOutput("A", "opt"))),
        ],
      }),
      makeStage("C", { writes: [makeWrite("done", "string")] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["C"]) });

    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({
        A: [{ opt: "first" }, {}], // first: opt present, re-entry: opt absent
        B: [{ out_b: "b1" }, { out_b: "b2" }],
        C: [{ done: "Done" }],
      }),
    });
    const result = await runtime.run({ task: "test" });
    expect(result.output).toEqual({ done: "Done" });
    expect(result.state.steps).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Cancellation via AbortSignal
// ---------------------------------------------------------------------------

describe("WorkflowRuntime.run — cancellation", () => {
  it("rejects when the abort signal is already aborted at a stage boundary", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("out_a", "string")],
        transitions: [makeTransition("B", 0, "go", guard.always())],
      }),
      makeStage("B", { writes: [makeWrite("out_b", "string")] }),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["B"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: {
        async execute() {
          // never returns; simulating a stage that completes after abort
          return { out_a: "x" };
        },
      },
    });
    const ac = new AbortController();
    ac.abort();
    await expect(
      runtime.run({ task: "t" }, { options: { signal: ac.signal } }),
    ).rejects.toThrow("cancelled");
  });

  it("stream() cancels the background run when the consumer breaks early", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("x", "string")],
        transitions: [makeTransition("A", 0, "loop", guard.always())],
      }),
    ];
    // infinite loop stage — will only stop via cancellation
    const manifest = makeManifest(stages, { exitIds: new Set() });
    let executeStarted = 0;
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: {
        async execute() {
          executeStarted++;
          // Yield control so the consumer can break the async iterator.
          await new Promise((r) => setTimeout(r, 5));
          return { x: "v" };
        },
      },
    });
    const ac = new AbortController();
    const iter = runtime.stream({ task: "t" }, { options: { signal: ac.signal } });
    // Consume one event then break.
    for await (const _event of iter) {
      void _event;
      break;
    }
    // Allow the run to settle after cancellation.
    await new Promise((r) => setTimeout(r, 30));
    // The run should have been cancelled (not still spinning stages forever).
    // executeStarted is at least 1 but should not grow unboundedly after break.
    const after = executeStarted;
    await new Promise((r) => setTimeout(r, 30));
    expect(executeStarted).toBe(after);
  });
});
