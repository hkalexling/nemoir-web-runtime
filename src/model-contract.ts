/**
 * NemoIR Web Runtime — model adapter contract.
 *
 * Ports the adapter protocol and request/response types from
 * `python/nemoir-runtime/src/nemoir_runtime/models.py`.
 */

import type { WorkflowEventChannel } from "./events.js";

export interface ModelToolCall {
  readonly id: string;
  readonly name: string;
  readonly arguments: Record<string, unknown>;
}

export interface ModelResponse {
  readonly content: string | null;
  readonly toolCalls?: readonly ModelToolCall[];
  readonly reasoning?: string | null;
}

export interface ModelRequest {
  readonly stageId: string;
  readonly messages: readonly Record<string, unknown>[];
  readonly tools: readonly Record<string, unknown>[];
  readonly outputSchema: Record<string, unknown>;
  readonly options: Record<string, unknown>;
  /** Cooperative cancellation signal. Adapters should abort long-running
   * model generation when this fires (e.g. WebLLM `engine.interruptGenerate()`). */
  readonly signal?: AbortSignal;
}

export type ModelStreamChunk =
  | { readonly kind: "delta"; readonly channel?: WorkflowEventChannel; readonly text?: string }
  | { readonly kind: "completed"; readonly response?: ModelResponse };

export interface ModelAdapter {
  complete(request: ModelRequest): Promise<ModelResponse>;
  stream?(request: ModelRequest): AsyncIterable<ModelStreamChunk>;
}

export interface ModelSpec {
  readonly name: string;
  readonly temperature?: number;
  readonly maxTokens?: number;
  readonly structuredOutputs?: boolean;
  readonly reasoning?: "none" | "raw";
  readonly extra?: Record<string, unknown>;
}

export interface ModelRouter {
  readonly default: string | Record<string, unknown> | ModelAdapter;
  readonly stages?: Record<string, string | Record<string, unknown> | ModelAdapter>;
}

export function supportsStreaming(adapter: object): boolean {
  return typeof (adapter as { stream?: unknown }).stream === "function";
}

/**
 * Resolve the effective reasoning mode.
 * RunOptions overrides adapter; else adapter default.
 */
export function resolveReasoningMode(
  adapterReasoning: string,
  override: string,
): "none" | "raw" {
  if (override && override !== "none") return "raw";
  return adapterReasoning === "raw" ? "raw" : "none";
}

/**
 * Select a model adapter for a stage, resolving ModelRouter if present.
 */
export function modelForStage(
  model: ModelAdapter | ModelRouter,
  stageId: string,
): ModelAdapter {
  if ("default" in model && "stages" in model) {
    // It's a ModelRouter
    const router = model as ModelRouter;
    const resolved = router.stages?.[stageId] ?? router.default;
    if (typeof resolved === "object" && "complete" in resolved) {
      return resolved as ModelAdapter;
    }
    throw new Error(
      `ModelRouter for stage '${stageId}' resolved to a non-adapter; string/mapping model specs require Phase 3+ adapters`,
    );
  }
  return model as ModelAdapter;
}
