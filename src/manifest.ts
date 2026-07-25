/**
 * NemoIR Web Runtime — manifest adapter.
 *
 * Converts the decoded raw IR JSON (snake_case, serde-tagged unions) into
 * ergonomic runtime-internal structures. Mirrors the manifest dataclasses
 * in `python/nemoir-runtime/src/nemoir_runtime/runtime.py`.
 *
 * `Read.origin` and `Node.annotations` are dropped here — they are
 * source-location metadata not needed at runtime.
 */

import type { WorkflowIrJson, ExprJson, GuardJson, RefJson } from "./ir.js";

// ---------------------------------------------------------------------------
// Runtime spec types (ergonomic, camelCase, discriminated unions)
// ---------------------------------------------------------------------------

export type RefSpec =
  | { readonly kind: "input"; readonly name: string }
  | { readonly kind: "node_output"; readonly node: string; readonly field: string }
  | { readonly kind: "bound"; readonly name: string };

export type ExprSpec =
  | { readonly kind: "not"; readonly expr: ExprSpec }
  | {
      readonly kind: "method_call";
      readonly receiver: ExprSpec;
      readonly method: string;
      readonly args: readonly ExprSpec[];
    }
  | { readonly kind: "ref"; readonly ref: RefSpec }
  | { readonly kind: "literal"; readonly type: string; readonly value: unknown }
  | { readonly kind: "and"; readonly exprs: readonly ExprSpec[] }
  | { readonly kind: "or"; readonly exprs: readonly ExprSpec[] }
  | {
      readonly kind: "compare";
      readonly op: string;
      readonly left: ExprSpec;
      readonly right: ExprSpec;
    }
  | {
      readonly kind: "binop";
      readonly op: string;
      readonly left: ExprSpec;
      readonly right: ExprSpec;
    };

export type GuardSpec =
  | { readonly kind: "always" }
  | { readonly kind: "has_value"; readonly ref: RefSpec }
  | { readonly kind: "missing"; readonly ref: RefSpec }
  | { readonly kind: "eq"; readonly left: ExprSpec; readonly right: ExprSpec }
  | { readonly kind: "if"; readonly cond: ExprSpec };

export interface ReadSpec {
  readonly ref: RefSpec;
  readonly optional: boolean;
}

export interface WriteSpec {
  readonly name: string;
  readonly type: string;
  readonly optional: boolean;
}

export interface TransitionSpec {
  readonly to: string;
  readonly priority: number;
  readonly reason: string;
  readonly guard: GuardSpec;
}

export interface StageExecutionSpec {
  readonly kind: "model" | "tool";
  readonly capability?: string;
  readonly args?: ReadonlyMap<string, ExprSpec>;
}

export interface StageSpec {
  readonly id: string;
  readonly prompt: string;
  readonly reads: readonly ReadSpec[];
  readonly writes: readonly WriteSpec[];
  readonly requires: ReadonlySet<string>;
  readonly transitions: readonly TransitionSpec[];
  readonly execution: StageExecutionSpec;
}

export interface TriggerSpec {
  readonly capability: string;
  /** bound var name -> trigger arg name */
  readonly bind: ReadonlyMap<string, string>;
}

export interface RequiredCapabilitySpec {
  readonly capability: string;
  readonly args: ReadonlyMap<string, RefSpec>;
}

export interface PolicySpec {
  readonly id: string;
  readonly kind: "before" | "deny";
  readonly trigger: TriggerSpec;
  readonly requires: readonly RequiredCapabilitySpec[];
  readonly condition?: ExprSpec | null;
}

export interface InputSpec {
  readonly id: string;
  readonly type: string;
}

export interface WorkflowManifest {
  readonly workflowId: string;
  readonly entryStageId: string;
  readonly exitStageIds: ReadonlySet<string>;
  readonly inputs: readonly { readonly id: string; readonly type: string }[];
  readonly capabilities: ReadonlySet<string>;
  readonly policies: readonly PolicySpec[];
  readonly stages: readonly StageSpec[];
}

// ---------------------------------------------------------------------------
// Conversion from raw IR JSON to runtime manifest
// ---------------------------------------------------------------------------

function convertRef(ref: RefJson): RefSpec {
  switch (ref.kind) {
    case "input":
      return { kind: "input", name: ref.name };
    case "node_output":
      return { kind: "node_output", node: ref.node, field: ref.field };
    case "bound":
      return { kind: "bound", name: ref.name };
  }
}
function convertExpr(expr: ExprJson): ExprSpec {
  switch (expr.kind) {
    case "not":
      return { kind: "not", expr: convertExpr(expr.expr) };
    case "method_call":
      return {
        kind: "method_call",
        receiver: convertExpr(expr.receiver),
        method: expr.method,
        args: (expr.args ?? []).map(convertExpr),
      };
    case "ref":
      return { kind: "ref", ref: convertRef(expr.ref) };
    case "literal":
      return { kind: "literal", type: expr.type, value: expr.value };
    case "and":
      return { kind: "and", exprs: (expr.exprs ?? []).map(convertExpr) };
    case "or":
      return { kind: "or", exprs: (expr.exprs ?? []).map(convertExpr) };
    case "compare":
      return {
        kind: "compare",
        op: expr.op,
        left: convertExpr(expr.left),
        right: convertExpr(expr.right),
      };
    case "binop":
      return {
        kind: "binop",
        op: expr.op,
        left: convertExpr(expr.left),
        right: convertExpr(expr.right),
      };
  }
}
function convertGuard(guard: GuardJson): GuardSpec {
  switch (guard.kind) {
    case "always":
      return { kind: "always" };
    case "has_value":
      return { kind: "has_value", ref: convertRef(guard.ref) };
    case "missing":
      return { kind: "missing", ref: convertRef(guard.ref) };
    case "eq":
      return {
        kind: "eq",
        left: convertExpr(guard.left),
        right: convertExpr(guard.right),
      };
    case "if":
      return { kind: "if", cond: convertExpr(guard.cond) };
  }
}

/**
 * Convert a decoded raw IR JSON object into a runtime WorkflowManifest.
 *
 * Assumes the IR has already passed `decodeWorkflowIr` (zod + web checks).
 * `Read.origin` and `Node.annotations` are dropped.
 */
export function buildWorkflowManifest(ir: WorkflowIrJson): WorkflowManifest {
  const stages: StageSpec[] = ir.nodes.map((node) => {
    const execution: StageExecutionSpec = {
      kind: node.execution.kind,
      capability: node.execution.capability,
      args: node.execution.args
        ? new Map(
            Object.entries(node.execution.args).map(
              ([k, v]) => [k, convertExpr(v)] as const,
            ),
          )
        : undefined,
    };

    return {
      id: node.id,
      prompt: node.prompt,
      reads: node.reads.map((r) => ({
        ref: convertRef(r.ref),
        // origin is dropped
        optional: r.optional,
      })),
      writes: node.writes.map((w) => ({
        name: w.name,
        type: w.type,
        optional: w.optional,
      })),
      requires: new Set(node.requires.map((c) => c.capability)),
      transitions: node.transitions.map((t) => ({
        to: t.to,
        priority: t.priority,
        reason: t.reason,
        guard: convertGuard(t.guard),
      })),
      execution,
    };
  });

  const policies: PolicySpec[] = ir.policies.map((p) => {
    const bind = new Map<string, string>();
    for (const [boundVar, arg] of Object.entries(p.trigger.bind)) {
      bind.set(boundVar, arg.name);
    }

    const requires = (p.requires ?? []).map((req) => {
      const args = new Map<string, RefSpec>();
      for (const [argName, argVal] of Object.entries(req.args)) {
        args.set(argName, convertRef(argVal.ref));
      }
      return {
        capability: req.capability,
        args,
      };
    });

    return {
      id: p.id,
      kind: p.kind as "before" | "deny",
      trigger: {
        capability: p.trigger.capability,
        bind,
      },
      requires,
      condition: p.condition ? convertExpr(p.condition) : null,
    };
  });

  return {
    workflowId: ir.workflow.id,
    entryStageId: ir.workflow.entry,
    exitStageIds: new Set(ir.workflow.exits),
    inputs: ir.inputs.map((i) => ({ id: i.id, type: i.type })),
    capabilities: new Set(ir.capabilities),
    policies,
    stages,
  };
}
