/**
 * NemoIR Web Runtime — guard/expression evaluator.
 *
 * Ports the expression evaluation logic from
 * `python/nemoir-runtime/src/nemoir_runtime/runtime.py`:
 * `_eval_guard_expr`, `_eval_policy_expr`, `_eval_expr_impl`,
 * `_eval_method_call`, `_method_contains`, `_method_eq`,
 * `_method_starts_with`, `_eq`.
 *
 * Web-specific simplifications:
 * - No `path` type emulation (path branches are unreachable; web rejects
 *   `path` types at compile time and at decode time).
 * - Numeric `compare`/`binop` with `null` propagation is load-bearing
 *   (the crash→Reject path in `judge_candidate.nemo`).
 */

import type { ExprSpec, RefSpec, GuardSpec } from "./manifest.js";
import {
  DataUnavailableError,
  PolicyEvaluationError,
} from "./errors.js";

// ---------------------------------------------------------------------------
// Type checking helpers
// ---------------------------------------------------------------------------

// JS note: typeof true === "boolean", not "number", so a plain typeof check
// already excludes booleans. This mirrors Python's _is_number_value.

// ---------------------------------------------------------------------------
// Ref resolution context
// ---------------------------------------------------------------------------

/** Resolve a guard/transition ref against inputs and stage outputs. */
export type GuardRefResolver = (ref: RefSpec) => unknown;

/** Resolve a policy ref against inputs and bound args. */
export interface PolicyRefContext {
  readonly inputs: Record<string, unknown>;
  readonly boundArgs: Record<string, unknown>;
  readonly policyId: string;
  readonly capability: string;
}

export function resolveGuardRef(
  ref: RefSpec,
  inputs: Record<string, unknown>,
  stageOutputs: Record<string, Record<string, unknown>>,
): unknown {
  if (ref.kind === "bound") {
    throw new DataUnavailableError(
      `Guard refs bound variable '${ref.name}' which is policy-local only`,
    );
  }
  return resolveReadRef(ref, inputs, stageOutputs);
}

export function resolveReadRef(
  ref: RefSpec,
  inputs: Record<string, unknown>,
  stageOutputs: Record<string, Record<string, unknown>>,
): unknown {
  if (ref.kind === "input") {
    return inputs[ref.name];
  }
  if (ref.kind === "node_output") {
    const node = stageOutputs[ref.node];
    if (!node) return undefined;
    return node[ref.field];
  }
  // bound
  throw new DataUnavailableError(
    `Read refs bound variable '${ref.name}' which is policy-local only`,
  );
}

export function resolvePolicyRef(
  ref: RefSpec,
  ctx: PolicyRefContext,
): unknown {
  if (ref.kind === "input") {
    if (!(ref.name in ctx.inputs)) {
      throw new PolicyEvaluationError(
        `Policy '${ctx.policyId}' for capability '${ctx.capability}': input ref '${ref.name}' is not provided`,
      );
    }
    return ctx.inputs[ref.name];
  }
  if (ref.kind === "bound") {
    if (!(ref.name in ctx.boundArgs)) {
      throw new PolicyEvaluationError(
        `Policy '${ctx.policyId}' for capability '${ctx.capability}': bound ref '${ref.name}' could not be resolved`,
      );
    }
    return ctx.boundArgs[ref.name];
  }
  // node_output
  throw new PolicyEvaluationError(
    `Policy '${ctx.policyId}' for capability '${ctx.capability}': refs node_output '${ref.node}.${ref.field}' which is not allowed in policies`,
  );
}

// ---------------------------------------------------------------------------
// Expression evaluation
// ---------------------------------------------------------------------------

/**
 * Core expression evaluator.
 *
 * @param expr the expression to evaluate
 * @param resolve a function resolving RefSpec values
 * @param recurse a function evaluating sub-expressions (for recursion)
 */
export function evalExpr(
  expr: ExprSpec,
  resolve: (ref: RefSpec) => unknown,
  recurse: (e: ExprSpec) => unknown,
): unknown {
  switch (expr.kind) {
    case "ref":
      return resolve(expr.ref);
    case "literal":
      return expr.value;
    case "not":
      return !recurse(expr.expr);
    case "method_call":
      return evalMethodCall(
        expr.method,
        recurse(expr.receiver),
        expr.args.map((a) => recurse(a)),
      );
    case "and":
      return expr.exprs.every((e) => recurse(e));
    case "or":
      return expr.exprs.some((e) => recurse(e));
    case "compare":
      return evalCompare(expr, recurse);
    case "binop":
      return evalBinOp(expr, recurse);
  }
}

function evalCompare(
  expr: Extract<ExprSpec, { kind: "compare" }>,
  recurse: (e: ExprSpec) => unknown,
): unknown {
  const validOps = ["gt", "gte", "lt", "lte"];
  if (!validOps.includes(expr.op)) {
    throw new PolicyEvaluationError(
      `Unknown compare op '${expr.op}'; expected gt, gte, lt, or lte`,
    );
  }
  const leftVal = recurse(expr.left);
  const rightVal = recurse(expr.right);
  // None propagation: fail-closed for guards
  if (leftVal === null || leftVal === undefined || rightVal === null || rightVal === undefined) {
    return false;
  }
  switch (expr.op) {
    case "gt":
      return (leftVal as number) > (rightVal as number);
    case "gte":
      return (leftVal as number) >= (rightVal as number);
    case "lt":
      return (leftVal as number) < (rightVal as number);
    case "lte":
      return (leftVal as number) <= (rightVal as number);
    default:
      return false;
  }
}

function evalBinOp(
  expr: Extract<ExprSpec, { kind: "binop" }>,
  recurse: (e: ExprSpec) => unknown,
): unknown {
  const validOps = ["add", "sub", "mul", "div"];
  if (!validOps.includes(expr.op)) {
    throw new PolicyEvaluationError(
      `Unknown binop '${expr.op}'; expected add, sub, mul, or div`,
    );
  }
  const leftVal = recurse(expr.left);
  const rightVal = recurse(expr.right);
  // None propagation: return null (SQL-null-style)
  if (leftVal === null || leftVal === undefined || rightVal === null || rightVal === undefined) {
    return null;
  }
  switch (expr.op) {
    case "add":
      return (leftVal as number) + (rightVal as number);
    case "sub":
      return (leftVal as number) - (rightVal as number);
    case "mul":
      return (leftVal as number) * (rightVal as number);
    case "div":
      if ((rightVal as number) === 0) {
        throw new PolicyEvaluationError("Division by zero in binop");
      }
      return (leftVal as number) / (rightVal as number);
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Method calls
// ---------------------------------------------------------------------------

function evalMethodCall(
  method: string,
  receiverVal: unknown,
  argVals: unknown[],
): unknown {
  switch (method) {
    case "contains":
      return methodContains(receiverVal, argVals);
    case "eq":
      return methodEq(receiverVal, argVals);
    case "starts_with":
      return methodStartsWith(receiverVal, argVals);
    default:
      throw new DataUnavailableError(`Unknown method '${method}'`);
  }
}

function methodContains(receiverVal: unknown, argVals: unknown[]): unknown {
  if (argVals.length !== 1) {
    throw new DataUnavailableError("contains() requires exactly 1 argument");
  }
  const target = argVals[0];

  if (typeof receiverVal === "string") {
    // string.contains(string) — substring match
    if (typeof target !== "string") {
      throw new DataUnavailableError(
        `string.contains() argument must be string, got ${typeof target}`,
      );
    }
    return receiverVal.includes(target);
  }

  // Path branch is unreachable on web (path types rejected)
  throw new DataUnavailableError(
    `contains() receiver must be string, got ${typeof receiverVal}`,
  );
}

function methodEq(receiverVal: unknown, argVals: unknown[]): unknown {
  if (argVals.length !== 1) {
    throw new DataUnavailableError("eq() requires exactly 1 argument");
  }
  const arg = argVals[0];
  // Defensive: reject numeric operands (ordering-only rule, §3.4)
  if (typeof receiverVal === "number" || typeof arg === "number") {
    throw new PolicyEvaluationError(
      "eq() does not support number operands; use a compare predicate (>, >=, <, <=)",
    );
  }
  return eq(receiverVal, arg);
}

function methodStartsWith(receiverVal: unknown, argVals: unknown[]): unknown {
  if (argVals.length !== 1) {
    throw new DataUnavailableError("starts_with() requires exactly 1 argument");
  }
  if (typeof receiverVal !== "string") {
    throw new DataUnavailableError(
      `starts_with() receiver must be string, got ${typeof receiverVal}`,
    );
  }
  const arg = argVals[0];
  if (typeof arg !== "string") {
    throw new DataUnavailableError(
      `starts_with() argument must be string, got ${typeof arg}`,
    );
  }
  return receiverVal.startsWith(arg);
}

/** Raw equality for non-numeric, non-path values (strings/bools). */
function eq(a: unknown, b: unknown): boolean {
  // Both strings or bools — raw equality is correct (no path normalization needed on web)
  return a === b;
}

// ---------------------------------------------------------------------------
// Guard evaluation
// ---------------------------------------------------------------------------

export function evaluateGuard(
  guard: GuardSpec,
  inputs: Record<string, unknown>,
  stageOutputs: Record<string, Record<string, unknown>>,
): boolean {
  const resolve = (ref: RefSpec): unknown =>
    resolveGuardRef(ref, inputs, stageOutputs);
  const recurse = (e: ExprSpec): unknown =>
    evalExpr(e, resolve, recurse);

  switch (guard.kind) {
    case "always":
      return true;
    case "has_value":
      return resolve(guard.ref) !== null && resolve(guard.ref) !== undefined;
    case "missing":
      return resolve(guard.ref) === null || resolve(guard.ref) === undefined;
    case "eq": {
      const leftVal = recurse(guard.left);
      const rightVal = recurse(guard.right);
      // Defensive: reject numeric operands
      if (typeof leftVal === "number" || typeof rightVal === "number") {
        throw new PolicyEvaluationError(
          "GuardSpec(kind='eq') does not support number operands; use a compare predicate",
        );
      }
      return eq(leftVal, rightVal);
    }
    case "if": {
      const result = recurse(guard.cond);
      return Boolean(result);
    }
  }
}
