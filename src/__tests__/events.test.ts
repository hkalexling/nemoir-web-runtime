/**
 * Event streaming tests.
 *
 * Ports the web-safe subset of
 * `python/nemoir-runtime/tests/test_events.py`:
 * event ordering, monotonic sequencing, live streaming, failure events.
 */

import { describe, it, expect } from "vitest";
import { WorkflowRuntime } from "../runtime.js";
import { WorkflowEventEmitter } from "../events.js";
import { ToolRegistry } from "../tools.js";
import {
  scriptedExecutor,
  makeManifest,
  makeStage,
  makeWrite,
  makeTransition,
  guard,
} from "./helpers.js";
import {
  MaxStepsExceededError,
  NoTransitionMatchedError,
} from "../errors.js";
import type { StageSpec } from "../manifest.js";

function emptyRegistry(): ToolRegistry {
  return new ToolRegistry([]);
}

function simpleManifest(exitIds = new Set(["B"])): { manifest: WorkflowManifest; stages: StageSpec[] } {
  const stages: StageSpec[] = [
    makeStage("A", {
      writes: [makeWrite("out_a", "string")],
      transitions: [makeTransition("B", 0, "fallthrough", guard.always())],
    }),
    makeStage("B", { writes: [makeWrite("out_b", "string")] }),
  ];
  return { manifest: makeManifest(stages, { exitIds }), stages };
}

import type { WorkflowManifest } from "../manifest.js";

describe("WorkflowRuntime.stream — event ordering", () => {
  it("yields events in correct order", async () => {
    const { manifest } = simpleManifest();
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ out_a: "a" }], B: [{ out_b: "b" }] }),
    });

    const events: import("../events.js").WorkflowEvent[] = [];
    for await (const event of runtime.stream({ task: "t" })) {
      events.push(event);
    }

    const kinds = events.map((e) => e.kind);
    expect(kinds).toEqual([
      "run_started",
      "stage_started",
      "stage_completed",
      "transition_selected",
      "stage_started",
      "stage_completed",
      "run_completed",
    ]);
  });

  it("events have monotonic sequence numbers", async () => {
    const { manifest } = simpleManifest();
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ out_a: "a" }], B: [{ out_b: "b" }] }),
    });

    const events: import("../events.js").WorkflowEvent[] = [];
    for await (const event of runtime.stream({ task: "t" })) {
      events.push(event);
    }

    for (let i = 0; i < events.length; i++) {
      expect(events[i].sequence).toBe(i + 1);
    }
  });

  it("stage_started includes stage id", async () => {
    const { manifest } = simpleManifest();
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ out_a: "a" }], B: [{ out_b: "b" }] }),
    });

    const events: import("../events.js").WorkflowEvent[] = [];
    for await (const event of runtime.stream({ task: "t" })) {
      events.push(event);
    }

    const started = events.filter((e) => e.kind === "stage_started");
    expect(started[0].stageId).toBe("A");
    expect(started[1].stageId).toBe("B");
  });

  it("stage_completed includes output", async () => {
    const { manifest } = simpleManifest();
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ out_a: "a" }], B: [{ out_b: "final" }] }),
    });

    const events: import("../events.js").WorkflowEvent[] = [];
    for await (const event of runtime.stream({ task: "t" })) {
      events.push(event);
    }

    const completed = events.filter((e) => e.kind === "stage_completed");
    expect(completed[0].output).toEqual({ out_a: "a" });
    expect(completed[1].output).toEqual({ out_b: "final" });
  });

  it("run_completed includes result", async () => {
    const { manifest } = simpleManifest();
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ out_a: "a" }], B: [{ out_b: "b" }] }),
    });

    const events: import("../events.js").WorkflowEvent[] = [];
    for await (const event of runtime.stream({ task: "t" })) {
      events.push(event);
    }

    const rc = events.filter((e) => e.kind === "run_completed");
    expect(rc.length).toBe(1);
    const result = rc[0].result as { output: Record<string, unknown> } | null;
    expect(result).not.toBeNull();
    expect(result!.output).toEqual({ out_b: "b" });
  });

  it("run_started is first event", async () => {
    const { manifest } = simpleManifest();
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ out_a: "a" }], B: [{ out_b: "b" }] }),
    });

    const events: import("../events.js").WorkflowEvent[] = [];
    for await (const event of runtime.stream({ task: "t" })) {
      events.push(event);
    }

    expect(events[0].kind).toBe("run_started");
  });
});

describe("WorkflowRuntime.stream — failure events", () => {
  it("emits run_failed on max_steps", async () => {
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

    const events: import("../events.js").WorkflowEvent[] = [];
    await expect(async () => {
      for await (const event of runtime.stream({ task: "t" }, { options: { maxSteps: 3 } })) {
        events.push(event);
      }
    }).rejects.toThrow(MaxStepsExceededError);

    const kinds = events.map((e) => e.kind);
    expect(kinds).toContain("run_failed");
    const rf = events.filter((e) => e.kind === "run_failed");
    expect(rf.length).toBe(1);
    expect(rf[0].error).toContain("maxSteps");
  });

  it("emits run_failed on no_transition_matched", async () => {
    const stages: StageSpec[] = [
      makeStage("A", {
        writes: [makeWrite("x", "string")],
        transitions: [makeTransition("B", 0, "never", guard.eq(
          { kind: "literal", type: "bool", value: false },
          { kind: "literal", type: "bool", value: true },
        ))],
      }),
      makeStage("B", {}),
    ];
    const manifest = makeManifest(stages, { exitIds: new Set(["B"]) });
    const runtime = new WorkflowRuntime({
      manifest,
      tools: emptyRegistry(),
      stageExecutor: scriptedExecutor({ A: [{ x: "a" }] }),
    });

    const events: import("../events.js").WorkflowEvent[] = [];
    await expect(async () => {
      for await (const event of runtime.stream({ task: "t" })) {
        events.push(event);
      }
    }).rejects.toThrow(NoTransitionMatchedError);

    expect(events.map((e) => e.kind)).toContain("run_failed");
  });
});

describe("WorkflowEventEmitter", () => {
  it("is cheap when no sink is attached", async () => {
    const emitter = new WorkflowEventEmitter("test");
    expect(emitter.hasSink).toBe(false);

    const event = await emitter.emit("run_started");
    expect(event.kind).toBe("run_started");
    expect(event.runId).toBe("test");
    expect(event.sequence).toBe(1);
  });

  it("calls the sink when attached", async () => {
    const collected: import("../events.js").WorkflowEvent[] = [];
    const emitter = new WorkflowEventEmitter("r1", (e) => { collected.push(e); });
    expect(emitter.hasSink).toBe(true);

    await emitter.emit("run_started");
    await emitter.emit("stage_started", { stageId: "A" });

    expect(collected.length).toBe(2);
    expect(collected[0].kind).toBe("run_started");
    expect(collected[1].kind).toBe("stage_started");
    expect(collected[0].sequence).toBe(1);
    expect(collected[1].sequence).toBe(2);
  });
});
