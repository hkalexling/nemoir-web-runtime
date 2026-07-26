/**
 * NemoIR Web Runtime — raw IR JSON decoder.
 *
 * Strict zod schema that decodes the `workflow.json` emitted by
 * `nemo compile --target web`. The JSON uses serde's snake_case field
 * names and `kind`-tagged unions, matching `compiler/crates/nemoir-ir/src/lib.rs`.
 *
 * This module only validates structure + web-target defensiveness. It does
 * not replicate the full graph reachability / type-checking that the Rust
 * `nemoir_ir::validate` does — that runs at compile time. Here we defensively
 * reject web-incompatible constructs (`path` types, `fs.*`/`os.shell`
 * capabilities, deterministic `tool` stages) so a hand-authored manifest
 * cannot bypass the compile-time contract.
 */

import { z } from "zod";
import {
  isWebAllowedCapability,
  WEB_DETERMINISTIC_ONLY_CAPABILITIES,
} from "./capabilities.js";

// ---------------------------------------------------------------------------
// Raw IR JSON types (snake_case, matching serde output)
// ---------------------------------------------------------------------------

export const RefJson = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("input"),
    name: z.string(),
  }),
  z.object({
    kind: z.literal("node_output"),
    node: z.string(),
    field: z.string(),
  }),
  z.object({
    kind: z.literal("bound"),
    name: z.string(),
  }),
]);
export type RefJson = z.infer<typeof RefJson>;

export type ExprJson =
  | { kind: "not"; expr: ExprJson }
  | { kind: "method_call"; receiver: ExprJson; method: string; args?: ExprJson[] }
  | { kind: "ref"; ref: RefJson }
  | { kind: "literal"; type: string; value?: unknown }
  | { kind: "and"; exprs?: ExprJson[] }
  | { kind: "or"; exprs?: ExprJson[] }
  | { kind: "compare"; op: string; left: ExprJson; right: ExprJson }
  | { kind: "binop"; op: string; left: ExprJson; right: ExprJson };

export const ExprJson: z.ZodType<ExprJson> = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("not"),
    expr: z.lazy(() => ExprJson),
  }),
  z.object({
    kind: z.literal("method_call"),
    receiver: z.lazy(() => ExprJson),
    method: z.string(),
    args: z.array(z.lazy(() => ExprJson)).default([]),
  }),
  z.object({
    kind: z.literal("ref"),
    ref: RefJson,
  }),
  z.object({
    kind: z.literal("literal"),
    type: z.string(),
    // Literals may carry structured values (objects/arrays) for `json`-typed
    // exec params; the DSL emits these natively (grammar `json_value`), so the
    // decoder accepts any JSON value here rather than only scalars.
    value: z.unknown(),
  }),
  z.object({
    kind: z.literal("and"),
    exprs: z.array(z.lazy(() => ExprJson)).default([]),
  }),
  z.object({
    kind: z.literal("or"),
    exprs: z.array(z.lazy(() => ExprJson)).default([]),
  }),
  z.object({
    kind: z.literal("compare"),
    op: z.string(),
    left: z.lazy(() => ExprJson),
    right: z.lazy(() => ExprJson),
  }),
  z.object({
    kind: z.literal("binop"),
    op: z.string(),
    left: z.lazy(() => ExprJson),
    right: z.lazy(() => ExprJson),
  }),
]);

export const GuardJson = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("always") }),
  z.object({ kind: z.literal("has_value"), ref: RefJson }),
  z.object({ kind: z.literal("missing"), ref: RefJson }),
  z.object({ kind: z.literal("eq"), left: ExprJson, right: ExprJson }),
  z.object({ kind: z.literal("if"), cond: ExprJson }),
]);
export type GuardJson = z.infer<typeof GuardJson>;

// BindArg has kind="arg" and a name, linking a trigger param to a bound var
export const BindArgJson = z.object({
  kind: z.literal("arg"),
  name: z.string(),
});

// ArgValue for RequiredCapability.args is { kind: "ref", ref: RefJson }
export const ArgValueJson = z.object({
  kind: z.literal("ref"),
  ref: RefJson,
});

export const StageExecutionJson = z.object({
  kind: z.literal("model").or(z.literal("tool")),
  capability: z.string().optional(),
  args: z.record(z.string(), ExprJson).optional(),
}).default({ kind: "model" as const });

export const ReadJson = z.object({
  ref: RefJson,
  optional: z.boolean(),
  origin: z.string().default(""),
});

export const WriteJson = z.object({
  name: z.string(),
  type: z.string(),
  optional: z.boolean(),
});

export const TransitionJson = z.object({
  to: z.string(),
  priority: z.number(),
  reason: z.string(),
  guard: GuardJson,
});

export const StageCapabilityJson = z.object({
  capability: z.string(),
});

export const NodeJson = z.object({
  id: z.string(),
  annotations: z.array(z.string()).default([]),
  prompt: z.string(),
  reads: z.array(ReadJson),
  writes: z.array(WriteJson),
  requires: z.array(StageCapabilityJson),
  transitions: z.array(TransitionJson),
  execution: StageExecutionJson,
});

export const TriggerJson = z.object({
  capability: z.string(),
  bind: z.record(z.string(), BindArgJson).default({}),
});

export const RequiredCapabilityJson = z.object({
  capability: z.string(),
  args: z.record(z.string(), ArgValueJson).default({}),
});

export const PolicyJson = z.object({
  id: z.string(),
  kind: z.string(),
  trigger: TriggerJson,
  requires: z.array(RequiredCapabilityJson).optional(),
  condition: ExprJson.nullable().optional(),
});

export const InputJson = z.object({
  id: z.string(),
  type: z.string(),
});

export const WorkflowIrJson = z.object({
  ir_version: z.string(),
  kind: z.string(),
  source: z.object({
    frontend: z.string(),
    file: z.string(),
  }),
  workflow: z.object({
    id: z.string(),
    entry: z.string(),
    exits: z.array(z.string()),
    transition_semantics: z.object({
      selection: z.string(),
      no_match: z.string(),
    }),
  }),
  inputs: z.array(InputJson),
  capabilities: z.array(z.string()),
  policies: z.array(PolicyJson),
  nodes: z.array(NodeJson),
});
export type WorkflowIrJson = z.infer<typeof WorkflowIrJson>;

// ---------------------------------------------------------------------------
// Web-target defensiveness checks (post-decode)
// ---------------------------------------------------------------------------

/** Check whether an IR type string references the `path` type. */
function typeUsesPath(ty: string): boolean {
  return ty.includes("path");
}

export interface WebValidationIssue {
  readonly path: string;
  readonly message: string;
}

/**
 * Defensively reject web-incompatible constructs in a decoded IR.
 *
 * This mirrors `nemoir_backend_web::validate_for_web` as a runtime
 * backstop: if someone hand-authors a `workflow.json` with `path` types
 * or `fs.*` capabilities, the runtime rejects it at load time.
 */
export function validateForWeb(ir: WorkflowIrJson): WebValidationIssue[] {
  const issues: WebValidationIssue[] = [];

  // Top-level capabilities
  for (const cap of ir.capabilities) {
    if (!isWebAllowedCapability(cap)) {
      issues.push({
        path: "capabilities",
        message: `capability "${cap}" is not supported on the web target`,
      });
    }
  }

  // Inputs: reject path
  for (const inp of ir.inputs) {
    if (typeUsesPath(inp.type)) {
      issues.push({
        path: `inputs.${inp.id}`,
        message: `input "${inp.id}" has unsupported type "${inp.type}" on the web target`,
      });
    }
  }

  // Nodes
  for (const node of ir.nodes) {
    // Writes: reject path
    for (const w of node.writes) {
      if (typeUsesPath(w.type)) {
        issues.push({
          path: `nodes.${node.id}.writes.${w.name}`,
          message: `write "${w.name}" has unsupported type "${w.type}" on the web target`,
        });
      }
    }
    // Requires: only user.elicit / user.confirm
    for (const req of node.requires) {
      if (!isWebAllowedCapability(req.capability)) {
        issues.push({
          path: `nodes.${node.id}.requires`,
          message: `stage "${node.id}" requires unsupported capability "${req.capability}"`,
        });
      }
    }
    // Deterministic tool stages: allowed only for browser-supported capabilities
    if (node.execution.kind === "tool" && node.execution.capability) {
      if (!isWebAllowedCapability(node.execution.capability) &&
          !WEB_DETERMINISTIC_ONLY_CAPABILITIES.includes(node.execution.capability)) {
        issues.push({
          path: `nodes.${node.id}.execution`,
          message: `deterministic stage "${node.id}" uses capability "${node.execution.capability}" which is not supported on the web target`,
        });
      }
      // browser.js.run code must be a compile-time string literal
      if (node.execution.capability === "browser.js.run" && node.execution.args) {
        const codeExpr = node.execution.args["code"];
        if (!codeExpr) {
          issues.push({
            path: `nodes.${node.id}.execution.args`,
            message: `deterministic stage "${node.id}" (capability browser.js.run) is missing the required 'code' argument`,
          });
        } else if (codeExpr.kind !== "literal" || (codeExpr as { type: string }).type !== "string") {
          issues.push({
            path: `nodes.${node.id}.execution.args.code`,
            message: `deterministic stage "${node.id}" (capability browser.js.run) requires a literal string for the 'code' argument; input/output refs are not allowed`,
          });
        }
      }
    }
    // Reject deterministic-only capabilities in model stages
    if (node.execution.kind === "model") {
      for (const req of node.requires) {
        if (WEB_DETERMINISTIC_ONLY_CAPABILITIES.includes(req.capability)) {
          issues.push({
            path: `nodes.${node.id}.requires`,
            message: `stage "${node.id}" requires capability "${req.capability}" which is only allowed in deterministic (exec:) stages`,
          });
        }
      }
    }
  }

  // Policies
  for (const policy of ir.policies) {
    if (!isWebAllowedCapability(policy.trigger.capability)) {
      issues.push({
        path: `policies.${policy.id}`,
        message: `policy "${policy.id}" triggers unsupported capability "${policy.trigger.capability}"`,
      });
    }
    // Deterministic-only capabilities cannot be used in policies
    if (WEB_DETERMINISTIC_ONLY_CAPABILITIES.includes(policy.trigger.capability)) {
      issues.push({
        path: `policies.${policy.id}`,
        message: `policy "${policy.id}" triggers capability "${policy.trigger.capability}" which is deterministic-stage-only and cannot be used in policies`,
      });
    }
    if (policy.requires) {
      for (const req of policy.requires) {
        if (!isWebAllowedCapability(req.capability)) {
          issues.push({
            path: `policies.${policy.id}.requires`,
            message: `policy "${policy.id}" requires unsupported capability "${req.capability}"`,
          });
        }
        if (WEB_DETERMINISTIC_ONLY_CAPABILITIES.includes(req.capability)) {
          issues.push({
            path: `policies.${policy.id}.requires`,
            message: `policy "${policy.id}" requires capability "${req.capability}" which is deterministic-stage-only and cannot be used in policies`,
          });
        }
      }
    }
  }

  return issues;
}

/**
 * Decode and web-validate raw IR JSON.
 *
 * @throws {Error} if zod parsing fails or web-target checks fail.
 */
export function decodeWorkflowIr(raw: unknown): WorkflowIrJson {
  const ir = WorkflowIrJson.parse(raw);
  const issues = validateForWeb(ir);
  if (issues.length > 0) {
    const messages = issues.map((i) => `${i.path}: ${i.message}`);
    throw new Error(
      `workflow is not compatible with the web target:\n${messages.join("\n")}`,
    );
  }
  return ir;
}
