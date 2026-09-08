/**
 * NemoIR Web Runtime — event system.
 *
 * Ports `python/nemoir-runtime/src/nemoir_runtime/events.py`.
 *
 * 14 event kinds, 5 channels, monotonic per-run sequencing, tz-aware ISO
 * timestamps. The emitter is cheap when no sink is attached.
 */

import type { WorkflowResult } from "./runtime-types.js";

export type WorkflowEventKind =
  | "run_started"
  | "stage_started"
  | "model_delta"
  | "model_completed"
  | "model_retry"
  | "tool_call_started"
  | "tool_call_completed"
  | "tool_call_failed"
  | "policy_checked"
  | "policy_denied"
  | "transition_selected"
  | "stage_completed"
  | "run_completed"
  | "run_failed";

export type WorkflowEventChannel =
  | "assistant"
  | "progress"
  | "reasoning"
  | "reasoning_summary"
  | "debug";

export interface WorkflowEvent {
  readonly kind: WorkflowEventKind;
  readonly runId: string;
  readonly sequence: number;
  readonly timestamp: string; // ISO 8601
  readonly stageId?: string;
  readonly channel?: WorkflowEventChannel | null;
  readonly text?: string | null;
  readonly capability?: string | null;
  readonly toolName?: string | null;
  readonly args?: Record<string, unknown> | null;
  readonly output?: Record<string, unknown> | null;
  readonly result?: WorkflowResult | unknown | null;
  readonly error?: string | null;
  readonly transitionTo?: string | null;
  readonly metadata?: Record<string, unknown>;
}

export type WorkflowEventSink = (event: WorkflowEvent) => Promise<void> | void;

/**
 * Per-run event emitter with monotonic sequencing.
 *
 * The emitter is cheap when the sink is `null`: `emit()` still constructs
 * and returns the event (for tests) but no I/O happens.
 */
export type WorkflowEventObserver = (event: WorkflowEvent) => unknown | Promise<unknown>;

export class WorkflowEventEmitter {
  private _seq = 0;
  private readonly _runId: string;
  private readonly _sink: WorkflowEventSink | null;
  private readonly _observer: WorkflowEventObserver | null;

  constructor(
    runId: string,
    sink?: WorkflowEventSink | null,
    observer?: WorkflowEventObserver | null,
  ) {
    this._runId = runId;
    this._sink = sink ?? null;
    this._observer = observer ?? null;
  }

  get runId(): string {
    return this._runId;
  }

  get sequence(): number {
    return this._seq;
  }

  /** True when an actual consumer is attached. */
  get hasSink(): boolean {
    return this._sink !== null;
  }

  /** Live-consumer check that ignores the trace observer (streaming gate). */
  get hasLiveSink(): boolean {
    return this._sink !== null;
  }

  get hasObserver(): boolean {
    return this._observer !== null;
  }

  async emit(
    kind: WorkflowEventKind,
    fields: Omit<WorkflowEvent, "kind" | "runId" | "sequence" | "timestamp"> = {},
  ): Promise<WorkflowEvent> {
    this._seq += 1;
    const event: WorkflowEvent = {
      kind,
      runId: this._runId,
      sequence: this._seq,
      timestamp: new Date().toISOString(),
      ...fields,
    };
    if (this._observer !== null) {
      try {
        await this._observer(event);
      } catch {
        // Observer failures must not change workflow outcome or prevent
        // the live sink from receiving the event.
      }
    }
    if (this._sink !== null) {
      await this._sink(event);
    }
    return event;
  }
}
