/**
 * NemoIR Web Runtime — WebLLM session + ModelAdapter.
 *
 * Framework-neutral: this module does not import React. The generated
 * `main.tsx` is one possible consumer (it supplies a `workerFactory` and
 * an `onProgress` callback); a vanilla host can use `createWebllmAdapter()`
 * directly with `WorkflowAgent`.
 *
 * `@mlc-ai/web-llm` is lazy-imported via dynamic `import()` so it is
 * code-split into a separate bundle chunk. Apps that never request a local
 * model do not pay the ~6 MB WebLLM main-thread cost on first paint; the
 * chunk only loads when `createWebllmSession()` or `ensureLoaded()` is first
 * called.
 *
 * The worker itself (`webllm.worker.ts`, emitted by the codegen crate) hosts
 * `WebWorkerMLCEngineHandler`; the main thread holds a `WebWorkerMLCEngine`
 * proxy exposing the OpenAI-shaped `engine.chat.completions.create(...)`.
 *
 * This is the **local privacy-preserving path**. No provider credential or
 * prompt leaves the browser. Cloud transport is Phase 4.
 */

import type {
  ModelAdapter,
  ModelRequest,
  ModelResponse,
  ModelStreamChunk,
} from "./model-contract.js";
import { ModelProviderError } from "./errors.js";

// Type-only imports — erased at emit time; do not add WebLLM to the
// main-thread bundle graph.
import type {
  AppConfig,
  ChatCompletionChunk,
  InitProgressReport,
  MLCEngineInterface,
  ModelRecord,
} from "@mlc-ai/web-llm";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface WebLlmProgressReport {
  readonly text: string;
  readonly progress: number;
  readonly timeElapsed: number;
}

export interface WebLlmModelInfo {
  readonly modelId: string;
  readonly label: string;
  readonly vramRequiredMb?: number;
  readonly lowResourceRequired?: boolean;
  readonly requiredFeatures?: readonly string[];
  /** True for models in WebLLM's `functionCallingModelIds` list. */
  readonly supportsFunctionCalling?: boolean;
}

export interface WebLlmSessionOptions {
  /** Creates the WebLLM worker. The generated app supplies:
   * `() => new Worker(new URL("./webllm.worker.ts", import.meta.url), { type: "module" })`. */
  readonly workerFactory: () => Worker;
  /** Model download/load progress callback (first-visit download can take minutes). */
  readonly onProgress?: (report: WebLlmProgressReport) => void;
  /** Extra (e.g. fine-tuned) model records appended to the prebuilt list. */
  readonly extraModels?: readonly ModelRecord[];
  /**
   * Cache backend override. Auto-detected by default: OPFS if the browser
   * supports it (best for large-model persistence), else IndexedDB.
   */
  readonly cacheBackend?: "opfs" | "indexeddb" | "cache" | "cross-origin";
}

export interface WebLlmSession {
  /** LLM models available to load (embeddings filtered out). */
  readonly models: readonly WebLlmModelInfo[];
  /** The model id currently loaded onto the engine, if any. */
  readonly currentModelId: string | undefined;
  /** True if `modelId` has been loaded (and not since unloaded). */
  isModelLoaded(modelId: string): boolean;
  /** IDs (from `models`) whose artifacts are present in the browser cache. */
  cachedModelIds(): Promise<readonly string[]>;
  /** Ensure `modelId` is loaded (download + WebGPU init on first visit). */
  ensureLoaded(modelId: string, signal?: AbortSignal): Promise<void>;
  /** Switch to a different model (unloads the current one first). */
  switchModel(modelId: string, signal?: AbortSignal): Promise<void>;
  /** Interrupt any in-flight generation. */
  interrupt(): Promise<void>;
  /** Dispose the worker and release resources. Safe to call multiple times. */
  dispose(): Promise<void>;
  /** The ModelAdapter backed by this session's engine. */
  readonly adapter: ModelAdapter;
}

// ---------------------------------------------------------------------------
// Lazy WebLLM module loader (cached)
// ---------------------------------------------------------------------------

type WebllmModule = typeof import("@mlc-ai/web-llm");

let webllmModulePromise: Promise<WebllmModule> | null = null;

function loadWebllm(): Promise<WebllmModule> {
  if (!webllmModulePromise) {
    // Dynamic import → Vite/Rollup code-splits this into a separate chunk.
    webllmModulePromise = import("@mlc-ai/web-llm");
  }
  return webllmModulePromise;
}

// ---------------------------------------------------------------------------
// Capability detection
// ---------------------------------------------------------------------------

/** True if this browser exposes the WebGPU API. */
export function isWebGPUAvailable(): boolean {
  return typeof navigator !== "undefined" && "gpu" in navigator;
}

/** True if cross-origin isolation (COOP/COEP) is active — needed for SharedArrayBuffer. */
export function isCrossOriginIsolated(): boolean {
  return typeof crossOriginIsolated === "boolean" ? crossOriginIsolated : false;
}

/** True if the Origin Private File System (OPFS) cache backend is usable. */
function isOpfsSupported(): boolean {
  try {
    return (
      typeof navigator !== "undefined" &&
      typeof navigator.storage === "object" &&
      navigator.storage !== null &&
      typeof navigator.storage.getDirectory === "function"
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Model list helpers
// ---------------------------------------------------------------------------

function humanizeModelId(modelId: string): string {
  // Remove common "-MLC" suffix and replace separators with spaces.
  return modelId
    .replace(/-MLC(-1k)?$/i, "")
    .replace(/[-_]/g, " ")
    .trim();
}

function toModelInfo(record: ModelRecord, functionCallingIds: ReadonlySet<string>): WebLlmModelInfo {
  return {
    modelId: record.model_id,
    label: humanizeModelId(record.model_id),
    vramRequiredMb: record.vram_required_MB,
    lowResourceRequired: record.low_resource_required,
    requiredFeatures: record.required_features,
    supportsFunctionCalling: functionCallingIds.has(record.model_id),
  };
}

function isLlmModel(record: ModelRecord): boolean {
  // Filter out embedding models. `model_type` is optional; embedding models
  // (ModelType.embedding === 1) and any "-embed-" id are excluded.
  if ((record as { model_type?: number }).model_type === 1) return false;
  if (record.model_id.toLowerCase().includes("embed")) return false;
  return true;
}

// ---------------------------------------------------------------------------
// WebLLM adapter
// ---------------------------------------------------------------------------

/**
 * Build a ModelAdapter backed by a WebLLM engine.
 *
 * Both `complete()` and `stream()` use WebLLM's streaming completion path
 * internally. This avoids the known non-streaming interrupt edge cases
 * (mlc-ai/web-llm#447, #596) — streaming interrupt is the reliable path.
 */
export function createWebllmAdapter(
  engineProvider: () => MLCEngineInterface | undefined,
  interrupt: () => Promise<void>,
): ModelAdapter {
  function buildParams(request: ModelRequest) {
    const opts = request.options as Record<string, unknown>;
    // Low default temperature is critical for small local LLMs to follow the
    // tagged-envelope protocol reliably. Allow per-stage override via options.temperature.
    const temperature =
      typeof opts?.temperature === "number" ? (opts.temperature as number) : 0.2;
    const maxTokens =
      typeof opts?.max_tokens === "number"
        ? (opts.max_tokens as number)
        : typeof opts?.maxTokens === "number"
          ? (opts.maxTokens as number)
          : undefined;
    const params: Record<string, unknown> = {
      messages: request.messages,
      stream: true,
      temperature,
    };
    if (maxTokens !== undefined) params.max_tokens = maxTokens;
    // Note: we deliberately do NOT set response_format here. WebLLM's
    // `json_object` mode routes through a grammar compiler that requires a
    // string `schema` and crashes when it is absent (BindingError). The
    // tagged-envelope protocol already instructs the model via the system
    // prompt to emit JSON, and ModelStageExecutor parses + retries malformed
    // JSON — that is the portable, model-agnostic baseline.
    return params;
  }

  async function* runStream(
    request: ModelRequest,
  ): AsyncGenerator<ChatCompletionChunk, void, void> {
    const engine = engineProvider();
    if (!engine) {
      throw new ModelProviderError(
        "WebLLM engine is not loaded; call session.ensureLoaded(modelId) before running.",
      );
    }
    const ac = new AbortController();
    const onAbort = () => {
      void interrupt();
    };
    if (request.signal) {
      if (request.signal.aborted) ac.abort();
      else request.signal.addEventListener("abort", onAbort, { once: true });
    }
    try {
      const stream = (await engine.chat.completions.create(
        buildParams(request) as unknown as Parameters<typeof engine.chat.completions.create>[0],
      )) as AsyncIterable<ChatCompletionChunk>;
      yield* stream;
    } finally {
      if (request.signal) request.signal.removeEventListener("abort", onAbort);
    }
  }

  async function consume(request: ModelRequest): Promise<ModelResponse> {
    let content = "";
    for await (const chunk of runStream(request)) {
      const delta = chunk.choices[0]?.delta?.content;
      if (delta) content += delta;
    }
    return { content: content || null, toolCalls: [], reasoning: null };
  }

  async function* stream(request: ModelRequest): AsyncIterable<ModelStreamChunk> {
    let content = "";
    for await (const chunk of runStream(request)) {
      const delta = chunk.choices[0]?.delta?.content;
      if (delta) {
        content += delta;
        yield { kind: "delta", channel: "assistant", text: delta };
      }
    }
    yield { kind: "completed", response: { content: content || null, toolCalls: [], reasoning: null } };
  }

  return {
    complete: consume,
    stream,
  };
}

// ---------------------------------------------------------------------------
// WebLlmSession
// ---------------------------------------------------------------------------

export class WebLlmSessionImpl implements WebLlmSession {
  private readonly opts: WebLlmSessionOptions;
  private readonly modelInfos: WebLlmModelInfo[];
  private engine?: MLCEngineInterface;
  private worker?: Worker;
  private loadedModelId?: string;
  private unhealthy = false;
  private loadPromise?: Promise<void>;

  constructor(opts: WebLlmSessionOptions) {
    this.opts = opts;
    // Build the model list eagerly from the statically-known prebuilt config.
    // (prebuiltAppConfig is a constant; importing its types is free.)
    // We resolve the actual records lazily at load time.
    this.modelInfos = [];
  }

  get models(): readonly WebLlmModelInfo[] {
    return this.modelInfos;
  }

  get currentModelId(): string | undefined {
    return this.loadedModelId;
  }

  isModelLoaded(modelId: string): boolean {
    return this.loadedModelId === modelId && !this.unhealthy;
  }

  private cachedPromise?: Promise<readonly string[]>;

  async cachedModelIds(): Promise<readonly string[]> {
    if (this.cachedPromise) return this.cachedPromise;
    this.cachedPromise = (async () => {
      await this.ensureModelList();
      const webllm = await loadWebllm();
      const appConfig: AppConfig = {
        model_list: [
          ...webllm.prebuiltAppConfig.model_list,
          ...(this.opts.extraModels ?? []),
        ],
        cacheBackend: this.cacheBackend,
      };
      const ids = this.modelInfos.map((m) => m.modelId);
      const results = await Promise.all(
        ids.map((id) =>
          webllm.hasModelInCache(id, appConfig).catch(() => false),
        ),
      );
      return ids.filter((_, i) => results[i]);
    })();
    // Allow re-querying after load/unload operations may change cache state.
    this.cachedPromise.finally(() => {
      // keep the memo; callers that want a refresh can call refreshCached()
    });
    return this.cachedPromise;
  }

  /** Drop the cached cache-state so the next `cachedModelIds()` re-queries. */
  invalidateCachedState(): void {
    this.cachedPromise = undefined;
  }

  private get cacheBackend(): AppConfig["cacheBackend"] {
    if (this.opts.cacheBackend) return this.opts.cacheBackend;
    return isOpfsSupported() ? "opfs" : "indexeddb";
  }

  /** Lazily populate the model list from WebLLM's prebuilt config. */
  async ensureModelList(): Promise<void> {
    if (this.modelInfos.length > 0) return;
    const webllm = await loadWebllm();
    const functionCalling = new Set(webllm.functionCallingModelIds);
    const records = [
      ...webllm.prebuiltAppConfig.model_list,
      ...(this.opts.extraModels ?? []),
    ];
    const infos = records
      .filter(isLlmModel)
      .map((r) => toModelInfo(r, functionCalling));
    // Mutate modelInfos in place (it's a readonly array reference held by
    // consumers after the first access, but we only populate once).
    (this.modelInfos as WebLlmModelInfo[]).push(...infos);
  }

  async ensureLoaded(modelId: string, signal?: AbortSignal): Promise<void> {
    if (this.isModelLoaded(modelId)) return;
    // Coalesce concurrent loads of the same model.
    if (this.loadPromise) {
      await this.loadPromise;
      if (this.isModelLoaded(modelId)) return;
    }
    this.loadPromise = this.loadModel(modelId, signal);
    try {
      await this.loadPromise;
    } finally {
      this.loadPromise = undefined;
    }
  }

  async switchModel(modelId: string, signal?: AbortSignal): Promise<void> {
    if (this.loadedModelId === modelId && !this.unhealthy) return;
    await this.unloadCurrent();
    await this.ensureLoaded(modelId, signal);
  }

  async interrupt(): Promise<void> {
    if (this.engine) {
      try {
        this.engine.interruptGenerate();
      } catch {
        // Best-effort; the worker may be mid-reload.
      }
    }
  }

  async dispose(): Promise<void> {
    await this.unloadCurrent();
    if (this.worker) {
      this.worker.terminate();
      this.worker = undefined;
    }
    this.engine = undefined;
    this.loadedModelId = undefined;
  }

  get adapter(): ModelAdapter {
    return createWebllmAdapter(
      () => this.engine,
      () => this.interrupt(),
    );
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  private async loadModel(modelId: string, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) throw new ModelProviderError("model load cancelled");
    const webllm = await loadWebllm();
    await this.ensureModelList();

    const appConfig: AppConfig = {
      model_list: [
        ...webllm.prebuiltAppConfig.model_list,
        ...(this.opts.extraModels ?? []),
      ],
      cacheBackend: this.cacheBackend,
    };

    // If the engine is unhealthy from a prior interrupted run, recreate it.
    if (this.unhealthy || !this.engine) {
      await this.unloadCurrent();
      if (!this.worker) this.worker = this.opts.workerFactory();
      const onProgress = this.opts.onProgress;
      this.engine = await webllm.CreateWebWorkerMLCEngine(
        this.worker,
        modelId,
        {
          appConfig,
          initProgressCallback: onProgress
            ? (r: InitProgressReport) =>
                onProgress({
                  text: r.text,
                  progress: r.progress,
                  timeElapsed: r.timeElapsed,
                })
            : undefined,
        },
      );
      this.unhealthy = false;
    } else {
      // Engine exists and is healthy — reload onto it.
      await this.engine.reload(modelId);
    }
    this.loadedModelId = modelId;
    this.invalidateCachedState();

    // If the load signal aborted mid-init, mark unhealthy so the next call
    // recreates the worker rather than relying on a half-loaded engine.
    if (signal?.aborted) {
      this.unhealthy = true;
      throw new ModelProviderError("model load cancelled");
    }
  }

  private async unloadCurrent(): Promise<void> {
    if (this.engine) {
      try {
        await this.engine.unload();
      } catch {
        // Ignore — the worker may already be gone.
      }
    }
    this.loadedModelId = undefined;
    this.unhealthy = false;
  }
}

/**
 * Create a WebLLM session.
 *
 * The session is framework-neutral and owns the worker lifecycle, model
 * loading, caching, and cancellation recovery. Pass `session.adapter` to
 * `WorkflowAgent` (or the generated `Agent`) as the `modelAdapter`.
 */
export async function createWebllmSession(
  opts: WebLlmSessionOptions,
): Promise<WebLlmSession> {
  if (!isWebGPUAvailable()) {
    throw new ModelProviderError(
      "WebGPU is not available in this browser. Use a WebGPU-capable browser " +
        "(Chrome/Edge 113+, Opera 99+) or a cloud endpoint (Phase 4).",
    );
  }
  const session = new WebLlmSessionImpl(opts);
  // Populate the model list so `session.models` is available immediately.
  await session.ensureModelList();
  return session;
}
