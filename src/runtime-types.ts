/**
 * NemoIR Web Runtime — core runtime types.
 *
 * Ports the result/state/options dataclasses and the stage execution
 * boundary from `python/nemoir-runtime/src/nemoir_runtime/runtime.py`.
 */

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
