/**
 * NemoIR Web Runtime — core runtime types.
 *
 * Ports the result/state/options dataclasses and the stage execution
 * boundary from `python/nemoir-runtime/src/nemoir_runtime/runtime.py`.
 */

/**
 * Context exposed to a consumer-provided semantic validator for a model stage.
 * It is deliberately data-only: validators can inspect the current stage and
 * bounded readable data, but cannot invoke tools or affect runtime state.
 */
export interface ModelStageOutputValidationContext {
  readonly stageId: string;
  readonly inputs: Readonly<Record<string, unknown>>;
  readonly readableContext: Readonly<Record<string, unknown>>;
}

/**
 * Result of semantic model-output validation. Return null/undefined for a
 * valid output, or one or more learner/model-facing correction messages.
 */
export type ModelStageOutputValidationResult =
  | string
  | readonly string[]
  | null
  | undefined
  | void;

/**
 * Optional per-stage semantic validation run inside ModelStageExecutor's
 * existing retry loop after structural output validation succeeds.
 */
export type ModelStageOutputValidator = (
  output: Readonly<Record<string, unknown>>,
  context: ModelStageOutputValidationContext,
) => ModelStageOutputValidationResult | Promise<ModelStageOutputValidationResult>;

/** Validators keyed by model-stage ID. */
export type ModelStageOutputValidators = Readonly<
  Record<string, ModelStageOutputValidator | undefined>
>;

export interface RunOptions {
  /** Max workflow steps before raising MaxStepsExceededError. Default 64. */
  readonly maxSteps: number;
  /** Max stage-output retries per stage. Default 3. 0 = hard-fail. */
  readonly maxModelRetries: number;
  /** Max tool-call rounds per stage. Default 32. null = unlimited. */
  readonly maxToolRounds: number | null;
  /** Accepted but not enforced (matches Python posture). Default null. */
  readonly timeoutSeconds: number | null;
  /** Per-run metadata propagated to ToolContext. Default {}. */
  readonly metadata: Record<string, unknown>;
  /** Reasoning channel mode. Default "none" (no hidden CoT). */
  readonly reasoning: "none" | "raw";
  /** Optional AbortSignal for cooperative cancellation. */
  readonly signal?: AbortSignal;
  /**
   * Optional semantic validators keyed by model-stage ID. A returned error is
   * sent back to the model through the normal stage-output retry path.
   */
  readonly modelOutputValidators?: ModelStageOutputValidators;
}

export const DEFAULT_RUN_OPTIONS: RunOptions = {
  maxSteps: 64,
  maxModelRetries: 3,
  maxToolRounds: 32,
  timeoutSeconds: null,
  metadata: {},
  reasoning: "none",
};

/**
 * Merge partial caller options with defaults.
 * Accepts Partial<RunOptions> for ergonomic call-site usage.
 */
export function resolveRunOptions(
  opts?: Partial<RunOptions>,
): RunOptions {
  if (!opts) return DEFAULT_RUN_OPTIONS;
  return {
    maxSteps: opts.maxSteps ?? DEFAULT_RUN_OPTIONS.maxSteps,
    maxModelRetries:
      opts.maxModelRetries ?? DEFAULT_RUN_OPTIONS.maxModelRetries,
    maxToolRounds: opts.maxToolRounds ?? DEFAULT_RUN_OPTIONS.maxToolRounds,
    timeoutSeconds:
      opts.timeoutSeconds ?? DEFAULT_RUN_OPTIONS.timeoutSeconds,
    metadata: opts.metadata ?? DEFAULT_RUN_OPTIONS.metadata,
    reasoning: opts.reasoning ?? DEFAULT_RUN_OPTIONS.reasoning,
    signal: opts.signal,
    modelOutputValidators: opts.modelOutputValidators ?? DEFAULT_RUN_OPTIONS.modelOutputValidators,
  };
}

export interface WorkflowState {
  readonly currentStageId: string;
  readonly stageOutputs: Record<string, Record<string, unknown>>;
  readonly steps: number;
}

export interface WorkflowResult {
  readonly output: Record<string, unknown>;
  readonly state: WorkflowState;
}

export type AgentResult<T> = {
  readonly output: T;
};
