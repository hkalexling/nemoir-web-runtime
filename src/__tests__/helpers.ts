/**
 * Test helpers: fake model adapter, scripted executor, manifest builders.
 *
 * Mirrors the fake-adapter pattern from
 * `python/nemoir-runtime/tests/test_model_stage_executor.py`.
 */

import type {
  ModelAdapter,
  ModelRequest,
  ModelResponse,
  ModelStreamChunk,
} from "../model-contract.js";
import type { StageContext, StageExecutor } from "../runtime.js";
import {
  type WorkflowManifest,
  type StageSpec,
  type WriteSpec,
  type ReadSpec,
  type TransitionSpec,
  type GuardSpec,
  type ExprSpec,
  type RefSpec,
  type InputSpec,
  type PolicySpec,
  type StageExecutionSpec,
} from "../manifest.js";

// ---------------------------------------------------------------------------
// Fake model adapter (for ModelStageExecutor tests)
// ---------------------------------------------------------------------------

export function fakeAdapter(responses: ModelResponse[]): {
  adapter: ModelAdapter;
  calls: ModelRequest[];
} {
  const calls: ModelRequest[] = [];
  const remaining = [...responses];
  const adapter: ModelAdapter = {
    async complete(request: ModelRequest): Promise<ModelResponse> {
      calls.push(request);
      const resp = remaining.shift();
      if (!resp) throw new Error("no more responses");
      return resp;
    },
  };
  return { adapter, calls };
}

export function fakeStreamingAdapter(chunks: ModelStreamChunk[]): {
  adapter: ModelAdapter;
  calls: ModelRequest[];
} {
  const calls: ModelRequest[] = [];
  const remaining = [...chunks];
  const adapter: ModelAdapter = {
    async complete(_request: ModelRequest): Promise<ModelResponse> {
      throw new Error("complete() not implemented; use stream()");
    },
    async *stream(request: ModelRequest): AsyncIterable<ModelStreamChunk> {
      calls.push(request);
      for (const chunk of remaining) {
        yield chunk;
      }
    },
  };
  return { adapter, calls };
}

// ---------------------------------------------------------------------------
// Scripted stage executor (for runtime tests without a model)
// ---------------------------------------------------------------------------

export function scriptedExecutor(
  outputsByStage: Record<string, Record<string, unknown>[]>,
): StageExecutor {
  const buckets: Record<string, Record<string, unknown>[]> = {};
  for (const [k, v] of Object.entries(outputsByStage)) {
    buckets[k] = [...v];
  }
  return {
    async execute(ctx: StageContext): Promise<Record<string, unknown>> {
      const bucket = buckets[ctx.stage.id];
      if (!bucket || bucket.length === 0) {
        throw new Error(`No scripted output for stage '${ctx.stage.id}'`);
      }
      return bucket.shift()!;
    },
  };
}

// ---------------------------------------------------------------------------
// Manifest builders
// ---------------------------------------------------------------------------

export function makeInput(id: string, type: string): InputSpec {
  return { id, type };
}

export function makeWrite(name: string, type: string, optional = false): WriteSpec {
  return { name, type, optional };
}

export function makeRead(ref: RefSpec, optional = false): ReadSpec {
  return { ref, optional };
}

export function makeTransition(
  to: string,
  priority: number,
  reason: string,
  guard: GuardSpec,
): TransitionSpec {
  return { to, priority, reason, guard };
}

export function makeStage(
  id: string,
  opts: {
    prompt?: string;
    reads?: ReadSpec[];
    writes?: WriteSpec[];
    requires?: Set<string>;
    transitions?: TransitionSpec[];
    execution?: StageExecutionSpec;
  } = {},
): StageSpec {
  return {
    id,
    prompt: opts.prompt ?? "test",
    reads: opts.reads ?? [],
    writes: opts.writes ?? [],
    requires: opts.requires ?? new Set(),
    transitions: opts.transitions ?? [],
    execution: opts.execution ?? { kind: "model" },
  };
}

export function makeManifest(
  stages: StageSpec[],
  opts: {
    workflowId?: string;
    entryId?: string;
    exitIds?: Set<string>;
    inputs?: InputSpec[];
    capabilities?: Set<string>;
    policies?: PolicySpec[];
  } = {},
): WorkflowManifest {
  return {
    workflowId: opts.workflowId ?? "TestWorkflow",
    entryStageId: opts.entryId ?? stages[0]?.id ?? "A",
    exitStageIds: opts.exitIds ?? new Set(["B"]),
    inputs: opts.inputs ?? [makeInput("task", "string")],
    capabilities: opts.capabilities ?? new Set(),
    policies: opts.policies ?? [],
    stages,
  };
}

// ---------------------------------------------------------------------------
// Expr/Guard builders (for compact test construction)
// ---------------------------------------------------------------------------

export const ref = {
  input(name: string): RefSpec {
    return { kind: "input", name };
  },
  nodeOutput(node: string, field: string): RefSpec {
    return { kind: "node_output", node, field };
  },
  bound(name: string): RefSpec {
    return { kind: "bound", name };
  },
};

export const expr = {
  ref(r: RefSpec): ExprSpec {
    return { kind: "ref", ref: r };
  },
  literal(type: string, value: unknown): ExprSpec {
    return { kind: "literal", type, value };
  },
  not(e: ExprSpec): ExprSpec {
    return { kind: "not", expr: e };
  },
  and(...exprs: ExprSpec[]): ExprSpec {
    return { kind: "and", exprs };
  },
  or(...exprs: ExprSpec[]): ExprSpec {
    return { kind: "or", exprs };
  },
  compare(op: string, left: ExprSpec, right: ExprSpec): ExprSpec {
    return { kind: "compare", op, left, right };
  },
  binop(op: string, left: ExprSpec, right: ExprSpec): ExprSpec {
    return { kind: "binop", op, left, right };
  },
  methodCall(receiver: ExprSpec, method: string, ...args: ExprSpec[]): ExprSpec {
    return { kind: "method_call", receiver, method, args };
  },
};

export const guard = {
  always(): GuardSpec {
    return { kind: "always" };
  },
  hasValue(r: RefSpec): GuardSpec {
    return { kind: "has_value", ref: r };
  },
  missing(r: RefSpec): GuardSpec {
    return { kind: "missing", ref: r };
  },
  eq(left: ExprSpec, right: ExprSpec): GuardSpec {
    return { kind: "eq", left, right };
  },
  if(cond: ExprSpec): GuardSpec {
    return { kind: "if", cond };
  },
};
