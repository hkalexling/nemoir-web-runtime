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
 * prompt leaves the browser.
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
  /**
   * Estimated download size in bytes. When absent the session uses
   * `vramRequiredMb * 1024 * 1024` as a heuristic. Set explicitly for
   * custom (extra) models whose download size differs from VRAM.
   */
  readonly estimatedDownloadBytes?: number;
}

export interface StorageCapacityAssessment {
  /** Whether `navigator.storage.estimate()` is available. */
  readonly supported: boolean;
  /** Total quota in bytes, or null if unavailable. */
  readonly quota: number | null;
  /** Current usage in bytes, or null if unavailable. */
  readonly usage: number | null;
  /** Available bytes (`quota - usage`), or null if unavailable. */
  readonly available: number | null;
  /** Estimated model download size in bytes. */
  readonly estimatedModelBytes: number;
  /** Conservative margin added to the estimate (bytes). */
  readonly marginBytes: number;
  /** True if the model is already cached. */
  readonly isCached: boolean;
  /** Best-effort likely-sufficiency judgment. */
  readonly likelySufficient: boolean;
  /** Human-readable summary of the assessment. */
  readonly message: string;
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
  /**
   * Optional per-model download-size overrides (bytes). Keys are model ids.
   * Use when a custom model's actual download size differs significantly
   * from the `vram_required_MB` heuristic.
   */
  readonly modelDownloadSizeOverrides?: Readonly<Record<string, number>>;
}

export type WebLlmLoadPhase =
  | "config_or_tokenizer"
  | "weight_shard"
  | "wasm_library"
  | "webgpu_init"
  | "cache_corruption"
  | "network"
  | "unknown";

/** Structured model-load failure, classified for diagnostics + recovery. */
export interface WebLlmLoadFailure {
  readonly modelId: string;
  readonly phase: WebLlmLoadPhase;
  /** Human-readable message, trimmed and capped for UI display. */
  readonly message: string;
  /** Failed artifact URL extracted from the error, when recoverable. */
  readonly failedUrl?: string;
  /** True when the error pattern suggests a corrupt/partial cached entry. */
  readonly suggestsCorruptCache: boolean;
}

export interface RetryLoadOptions {
  /** Delete all cached artifacts for the model before loading. */
  readonly cleanCache?: boolean;
  /** Terminate and recreate the WebLLM worker before loading. */
  readonly freshWorker?: boolean;
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
  /**
   * Assess whether there is likely enough browser storage for a model
   * download. Cached models always return `likelySufficient: true`.
   * When storage estimates are unavailable, `supported` is false and
   * `likelySufficient` defaults to true (never block on missing API).
   */
  assessStorage(modelId: string): Promise<StorageCapacityAssessment>;
  /** Ensure `modelId` is loaded (download + WebGPU init on first visit). */
  ensureLoaded(modelId: string, signal?: AbortSignal): Promise<void>;
  /** Switch to a different model (unloads the current one first). */
  switchModel(modelId: string, signal?: AbortSignal): Promise<void>;
  /**
   * Retry loading `modelId`, optionally deleting its cached artifacts first
   * and/or recreating the WebLLM worker. Captures a fresh
   * {@link WebLlmLoadFailure} when it fails again.
   */
  retryLoad(modelId: string, opts?: RetryLoadOptions, signal?: AbortSignal): Promise<void>;
  /** Delete all cached artifacts for `modelId` (weights, wasm, config, tokenizer). */
  deleteModelArtifacts(modelId: string): Promise<void>;
  /** Last classified load failure, or null if the last load succeeded. */
  readonly lastLoadFailure: WebLlmLoadFailure | null;
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

function toModelInfo(
  record: ModelRecord,
  functionCallingIds: ReadonlySet<string>,
  downloadSizeOverrides?: Readonly<Record<string, number>>,
): WebLlmModelInfo {
  const override = downloadSizeOverrides?.[record.model_id];
  const estimatedDownloadBytes =
    override ??
    (record.vram_required_MB != null ? record.vram_required_MB * 1024 * 1024 : undefined);
  return {
    modelId: record.model_id,
    label: humanizeModelId(record.model_id),
    vramRequiredMb: record.vram_required_MB,
    lowResourceRequired: record.low_resource_required,
    requiredFeatures: record.required_features,
    supportsFunctionCalling: functionCallingIds.has(record.model_id),
    estimatedDownloadBytes,
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

/** Default generation cap. Stage outputs are small JSON, so 1024 tokens is
 * generous and prevents an unbounded model loop from streaming forever. */
const DEFAULT_MAX_TOKENS = 1024;

/** Small positive penalties discourage degenerate token repetition in small
 * local models. Callers may override via options.frequency_penalty /
 * options.presence_penalty. */
const DEFAULT_FREQUENCY_PENALTY = 0.5;
const DEFAULT_PRESENCE_PENALTY = 0.5;

/** Inspect accumulated content for a repeating block this often (in deltas). */
const REPETITION_CHECK_EVERY = 16;

/** A loop is declared when, for some block length B in this set, the tail of
 * the accumulated content is B repeated consecutively this many times. The
 * set covers both tight token loops (period 2–5, e.g. ```\n) and phrase-level
 * loops whose period is longer. Catches loops whose individual deltas differ. */
const REPETITION_MIN_REPEATS = 3;

/** Return true when the tail of `content` ends with a short block repeated
 * consecutively. Scans every block length from 2 up so patterns whose period
 * does not divide a fixed block size are still caught. */
function hasRepeatingTail(content: string): boolean {
  if (content.length < REPETITION_MIN_REPEATS * 2) return false;
  const maxBlock = Math.min(128, Math.floor(content.length / REPETITION_MIN_REPEATS));
  for (let blockLen = 2; blockLen <= maxBlock; blockLen++) {
    const slice = content.slice(-blockLen * REPETITION_MIN_REPEATS);
    const block = slice.slice(0, blockLen);
    let repeats = true;
    for (let i = 1; i < REPETITION_MIN_REPEATS; i++) {
      if (slice.slice(i * blockLen, (i + 1) * blockLen) !== block) {
        repeats = false;
        break;
      }
    }
    if (repeats) return true;
  }
  return false;
}

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
    // Bound generation so a small model that locks into a degenerate token
    // loop cannot stream forever. Stage outputs are small JSON objects, so
    // 1024 tokens is generous; callers may override via options.max_tokens.
    const maxTokens =
      typeof opts?.max_tokens === "number"
        ? (opts.max_tokens as number)
        : typeof opts?.maxTokens === "number"
          ? (opts.maxTokens as number)
          : DEFAULT_MAX_TOKENS;
    const params: Record<string, unknown> = {
      messages: request.messages,
      stream: true,
      temperature,
      max_tokens: maxTokens,
      // Small positive penalties directly discourage the degenerate token
      // repetition that small local models fall into. Callers may override.
      frequency_penalty:
        typeof opts?.frequency_penalty === "number"
          ? (opts.frequency_penalty as number)
          : DEFAULT_FREQUENCY_PENALTY,
      presence_penalty:
        typeof opts?.presence_penalty === "number"
          ? (opts.presence_penalty as number)
          : DEFAULT_PRESENCE_PENALTY,
    };
    // Grammar-constrained JSON for tool-less model stages. When a stage has
    // no callable tools, the runtime parses its output as direct JSON
    // (parsePlainStageOutput), so constraining generation to the stage's JSON
    // Schema via WebLLM's xgrammar backend guarantees a structurally valid
    // object by construction. Small models cannot then emit the malformed JSON
    // (missing commas, stray quotes, duplicate keys, output-contract echo)
    // that previously consumed the retry budget and occasionally hung a run.
    //
    // Tool-enabled stages keep the tagged-envelope protocol: a single static
    // schema cannot express "tool_call OR final envelope", and `structural_tag`
    // mode is WebLLM's dedicated tool-calling constrained path (future work).
    //
    // A `schema` string is always supplied. The schema-less `json_object`
    // path crashes WebLLM's grammar compiler (BindingError); the documented
    // usage is `json_object` + `schema`, which the `cs1k` model libraries are
    // built for. Set options.constrainedDecoding=false to opt out for a stage.
    const tools = Array.isArray(request.tools) ? request.tools : [];
    const schema = request.outputSchema as Record<string, unknown> | undefined;
    const schemaProps =
      schema && (schema.properties as Record<string, unknown> | undefined);
    const disableConstrained =
      opts?.constrainedDecoding === false ||
      opts?.constrained_decoding === false;
    if (
      !disableConstrained &&
      tools.length === 0 &&
      schemaProps &&
      Object.keys(schemaProps).length > 0
    ) {
      params.response_format = {
        type: "json_object",
        schema: JSON.stringify(schema),
      } as Record<string, unknown>;
    }
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
      // Degenerate-repetition guard. Small local models occasionally lock
      // into an endless token cycle (tight token loops OR phrase-level loops
      // whose individual deltas differ) that never reaches a stop token.
      // max_tokens bounds the worst case; this detects the loop on the
      // accumulated content and aborts early via interrupt() so the trace is
      // not flooded and the run is not blocked for the full token budget.
      // After interrupt, the stream ends and the truncated content surfaces
      // as a normal stage-output validation retry.
      let accumulated = "";
      let deltaSinceCheck = 0;
      let interrupted = false;
      for await (const chunk of stream) {
        yield chunk;
        const delta = chunk.choices[0]?.delta?.content ?? "";
        if (!delta) continue;
        accumulated += delta;
        if (++deltaSinceCheck >= REPETITION_CHECK_EVERY) {
          deltaSinceCheck = 0;
          if (hasRepeatingTail(accumulated)) {
            interrupted = true;
            break;
          }
        }
      }
      if (interrupted) {
        await interrupt();
      }
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
// Load-failure classifier
// ---------------------------------------------------------------------------

/**
 * Classify a WebLLM model-load error into a phase for diagnostics and
 * recovery routing.
 *
 * WebLLM downloads artifacts in this order: `mlc-chat-config.json`, the
 * WASM model library, the tokenizer files, and finally `params_shard_*.bin`
 * weight shards. GPU initialization happens between WASM and tokenizer
 * fetch. Each phase has recognizable error signatures.
 */
export function classifyLoadError(modelId: string, error: unknown): WebLlmLoadFailure {
  const raw = error instanceof Error ? error.message : String(error);
  const message = raw.length > 5e3 ? raw.slice(0, 5e3) + "…" : raw;
  const lower = raw.toLowerCase();

  // Extract a URL from the error message if present.
  let failedUrl: string | undefined;
  const urlMatch = raw.match(/https?:\/\/[^\s'"]+/i);
  if (urlMatch) failedUrl = urlMatch[0];

  // --- Phase detection (order matters; later phases override on URL match) ---
  let phase: WebLlmLoadPhase;

  // `Cache.add() encountered a network error` after a partial download can
  // leave a corrupt cache entry that never self-heals. Check this regardless
  // of which artifact phase was in progress.
  const corruptCachePattern = /cache\.add\(\) encountered a network error/i.test(raw);
  let suggestsCorruptCache = corruptCachePattern;

  if (failedUrl) {
    const u = failedUrl.toLowerCase();
    if (u.includes("params_shard") || u.endsWith(".bin")) {
      phase = "weight_shard";
    } else if (u.endsWith(".wasm") || u.includes("-webgpu.wasm")) {
      phase = "wasm_library";
    } else if (
      u.includes("mlc-chat-config") ||
      u.includes("tokenizer.json") ||
      u.includes("tokenizer.model")
    ) {
      phase = "config_or_tokenizer";
      // A config/tokenizer fetch that returns an error page or times out can
      // leave bad bytes that break subsequent JSON.parse.
      suggestsCorruptCache = suggestsCorruptCache || /cache\.add\(\) encountered a network error/i.test(raw);
    } else if (u.includes("huggingface.co") || u.includes("raw.githubusercontent.com")) {
      phase = failedUrl.includes(".wasm") ? "wasm_library" : "weight_shard";
    } else {
      phase = "network";
    }
  } else if (/syntaxerror|json|unexpected end of (json )?input/i.test(raw)) {
    // A JSON parse failure almost always means a truncated/corrupt cached
    // mlc-chat-config.json or tokenizer response (e.g. a partial download
    // that HTTP 200'd with an error page body).
    phase = "cache_corruption";
    suggestsCorruptCache = true;
  } else if (
    /webgpu|gpu adapter|shader-f16|shader_f16|feature support|device was lost|insufficient memory/i.test(
      raw,
    )
  ) {
    phase = "webgpu_init";
  } else if (
    /networkerror|failed to fetch|network error|err_network|cache\.add\(\) encountered a network error|fetchfailed|timed out/i.test(
      lower,
    )
  ) {
    phase = "network";
  } else {
    phase = "unknown";
  }

  return { modelId, phase, message, failedUrl, suggestsCorruptCache };
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
  private _lastLoadFailure: WebLlmLoadFailure | null = null;

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

  get lastLoadFailure(): WebLlmLoadFailure | null {
    return this._lastLoadFailure;
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
    const overrides = this.opts.modelDownloadSizeOverrides;
    const infos = records
      .filter(isLlmModel)
      .map((r) => toModelInfo(r, functionCalling, overrides));
    // Mutate modelInfos in place (it's a readonly array reference held by
    // consumers after the first access, but we only populate once).
    (this.modelInfos as WebLlmModelInfo[]).push(...infos);
  }

  async ensureLoaded(modelId: string, signal?: AbortSignal): Promise<void> {
    if (this.isModelLoaded(modelId)) {
      this._lastLoadFailure = null;
      return;
    }
    // Coalesce concurrent loads of the same model.
    if (this.loadPromise) {
      await this.loadPromise;
      if (this.isModelLoaded(modelId)) {
        this._lastLoadFailure = null;
        return;
      }
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
    this._lastLoadFailure = null;
  }

  get adapter(): ModelAdapter {
    return createWebllmAdapter(
      () => this.engine,
      () => this.interrupt(),
    );
  }

  // -----------------------------------------------------------------------
  // Storage assessment (Phase 5)
  // -----------------------------------------------------------------------

  async assessStorage(modelId: string): Promise<StorageCapacityAssessment> {
    await this.ensureModelList();

    // Is the model already cached?
    let isCached = false;
    try {
      const cached = await this.cachedModelIds();
      isCached = cached.includes(modelId);
    } catch {
      // If we can't determine cache state, assume not cached.
    }

    const modelInfo = this.modelInfos.find((m) => m.modelId === modelId);
    const estimatedModelBytes =
      modelInfo?.estimatedDownloadBytes ?? 0;

    // Conservative margin: max(512 MiB, 20% of estimated size).
    const marginBytes = Math.max(
      512 * 1024 * 1024,
      Math.round(estimatedModelBytes * 0.2),
    );

    // Try `navigator.storage.estimate()`.
    let supported = false;
    let quota: number | null = null;
    let usage: number | null = null;
    let available: number | null = null;

    try {
      if (
        typeof navigator !== "undefined" &&
        typeof navigator.storage === "object" &&
        navigator.storage !== null &&
        typeof (navigator.storage as { estimate?: unknown }).estimate === "function"
      ) {
        const est = await navigator.storage.estimate();
        if (est && typeof est.quota === "number" && typeof est.usage === "number") {
          supported = true;
          quota = est.quota;
          usage = est.usage;
          available = Math.max(0, quota - usage);
        }
      }
    } catch {
      // estimate() may throw (e.g. in opaque origins).
    }

    // Cached models always appear sufficient.
    if (isCached) {
      const gb = (estimatedModelBytes / (1024 * 1024 * 1024)).toFixed(1);
      return {
        supported,
        quota,
        usage,
        available,
        estimatedModelBytes,
        marginBytes,
        isCached: true,
        likelySufficient: true,
        message: estimatedModelBytes > 0
          ? `Model is cached (~${gb} GB). No new download needed.`
          : "Model is cached. No new download needed.",
      };
    }

    if (!supported || available === null) {
      // Cannot estimate; never block.
      const gb = (estimatedModelBytes / (1024 * 1024 * 1024)).toFixed(1);
      return {
        supported: false,
        quota: null,
        usage: null,
        available: null,
        estimatedModelBytes,
        marginBytes,
        isCached: false,
        likelySufficient: true,
        message: estimatedModelBytes > 0
          ? `Model is not cached (~${gb} GB estimated). Browser storage estimate is unavailable.`
          : "Storage estimate is unavailable.",
      };
    }

    const needed = estimatedModelBytes + marginBytes;
    const likelySufficient = available >= needed;

    const availGb = (available / (1024 * 1024 * 1024)).toFixed(1);
    const needGb = (needed / (1024 * 1024 * 1024)).toFixed(1);
    const modelGb = (estimatedModelBytes / (1024 * 1024 * 1024)).toFixed(1);

    const message = likelySufficient
      ? `~${availGb} GB available (estimated need: ~${needGb} GB including margin). Storage looks sufficient.`
      : `Only ~${availGb} GB available. The model needs an estimated ~${modelGb} GB plus ~${((marginBytes) / (1024 * 1024 * 1024)).toFixed(1)} GB safety margin (~${needGb} GB total). Storage may be insufficient. Free browser storage or choose a smaller model.`;

    return {
      supported,
      quota,
      usage,
      available,
      estimatedModelBytes,
      marginBytes,
      isCached: false,
      likelySufficient,
      message,
    };
  }

  async retryLoad(
    modelId: string,
    opts?: RetryLoadOptions,
    signal?: AbortSignal,
  ): Promise<void> {
    const cleanCache = opts?.cleanCache ?? false;
    const freshWorker = opts?.freshWorker ?? false;

    // Coalesce with an in-flight load of the same model when no recovery is
    // requested; a recovery retry must run on its own so it can mutate the
    // worker/cache state.
    if (!cleanCache && !freshWorker && this.loadPromise) {
      await this.loadPromise;
      if (this.isModelLoaded(modelId)) {
        this._lastLoadFailure = null;
        return;
      }
    }

    if (cleanCache) {
      await this.deleteModelArtifacts(modelId).catch(() => {
        // Best-effort: a cache-delete failure should not block retry.
      });
      this.invalidateCachedState();
    }

    if (freshWorker || cleanCache) {
      // Force loadModel to recreate the worker + engine rather than reload
      // onto a possibly-corrupted engine.
      await this.unloadCurrent();
      if (this.worker) {
        this.worker.terminate();
        this.worker = undefined;
      }
      this.unhealthy = true;
    }

    this.loadPromise = this.loadModel(modelId, signal);
    try {
      await this.loadPromise;
      this._lastLoadFailure = null;
    } finally {
      this.loadPromise = undefined;
    }
  }

  async deleteModelArtifacts(modelId: string): Promise<void> {
    const webllm = await loadWebllm();
    await this.ensureModelList();
    const appConfig: AppConfig = {
      model_list: [
        ...webllm.prebuiltAppConfig.model_list,
        ...(this.opts.extraModels ?? []),
      ],
      cacheBackend: this.cacheBackend,
    };
    await webllm.deleteModelAllInfoInCache(modelId, appConfig);
    this.invalidateCachedState();
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

    try {
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
      this._lastLoadFailure = null;
    } catch (error) {
      // A failed init corrupts engine state and possibly the cache; mark the
      // engine unhealthy so retryLoad recreates it rather than calling
      // reload() on a half-initialized engine.
      this.unhealthy = true;
      if (error instanceof ModelProviderError) throw error;
      this._lastLoadFailure = classifyLoadError(modelId, error);
      throw error;
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
        "(Chrome/Edge 113+, Opera 99+).",
    );
  }
  const session = new WebLlmSessionImpl(opts);
  // Populate the model list so `session.models` is available immediately.
  await session.ensureModelList();
  return session;
}
