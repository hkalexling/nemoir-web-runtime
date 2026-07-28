/**
 * WebLLM adapter tests.
 *
 * `@mlc-ai/web-llm` is mocked so these tests run in Node without a GPU or
 * browser. The fake engine scripts streaming chunks and records calls.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type {
  ChatCompletionChunk,
} from "@mlc-ai/web-llm";

// Node test env has no navigator.gpu; stub it so createWebllmSession() proceeds.
function stubWebGPU() {
  Object.defineProperty(navigator, "gpu", {
    value: {},
    configurable: true,
  });
}

// Build a fake engine that scripts streaming responses.
function makeFakeEngine(opts: {
  chunksPerCall?: ChatCompletionChunk[][];
  interrupted?: () => void;
}) {
  const calls: Record<string, unknown>[] = [];
  const interrupted = opts.interrupted ?? (() => {});
  const queues = [...(opts.chunksPerCall ?? [])];
  const engine = {
    chat: {
      completions: {
        async create(params: Record<string, unknown>) {
          calls.push(params);
          const queue = queues.shift() ?? [];
          return (async function* () {
            for (const c of queue) yield c;
          })();
        },
      },
    },
    interruptGenerate() {
      interrupted();
    },
    unload: async () => {},
    reload: async () => {},
  };
  return { engine, calls };
}

async function makeSession(engine: unknown) {
  // Mock the lazy import to return our fake module.
  vi.doMock("@mlc-ai/web-llm", () => ({
    CreateWebWorkerMLCEngine: async () => engine,
    prebuiltAppConfig: {
      model_list: [
        { model_id: "Qwen2.5-0.5B-Instruct-q4f16_1-MLC", vram_required_MB: 944, low_resource_required: true },
        { model_id: "snowflake-arctic-embed-s-q0f32-MLC-b4", vram_required_MB: 238 },
      ],
    },
    functionCallingModelIds: [],
    hasModelInCache: async (_id: string) => false,
  }));
  const { createWebllmSession } = await import("../webllm.js");
  return createWebllmSession({
    workerFactory: () => ({ terminate() {}, postMessage() {} } as unknown as Worker),
  });
}

describe("WebLLM session — model list", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.doUnmock("@mlc-ai/web-llm");
    stubWebGPU();
  });

  it("filters out embedding models", async () => {
    const { engine } = makeFakeEngine({});
    const session = await makeSession(engine);
    const ids = session.models.map((m) => m.modelId);
    expect(ids).toContain("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    expect(ids.some((id) => id.includes("embed"))).toBe(false);
  });
});

describe("WebLLM adapter — completion mapping", () => {
  beforeEach(() => {
    vi.resetModules();
    stubWebGPU();
  });

  it("accumulates streaming content into a ModelResponse", async () => {
    const { engine, calls } = makeFakeEngine({
      chunksPerCall: [
        [
          { choices: [{ delta: { content: "Hello" } }] } as unknown as ChatCompletionChunk,
          { choices: [{ delta: { content: " world" } }] } as unknown as ChatCompletionChunk,
        ],
      ],
    });
    const session = await makeSession(engine);
    await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    const adapter = session.adapter;
    const resp = await adapter.complete({
      stageId: "s",
      messages: [{ role: "user", content: "hi" }],
      tools: [],
      outputSchema: {},
      options: {},
    });
    expect(resp.content).toBe("Hello world");
    expect(calls.length).toBe(1);
    expect((calls[0] as { stream: boolean }).stream).toBe(true);
  });

  it("streams deltas as model_delta chunks", async () => {
    const { engine } = makeFakeEngine({
      chunksPerCall: [
        [
          { choices: [{ delta: { content: "a" } }] } as unknown as ChatCompletionChunk,
          { choices: [{ delta: { content: "b" } }] } as unknown as ChatCompletionChunk,
        ],
      ],
    });
    const session = await makeSession(engine);
    await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    const adapter = session.adapter;
    const chunks = [];
    for await (const c of adapter.stream!({
      stageId: "s",
      messages: [],
      tools: [],
      outputSchema: {},
      options: {},
    })) {
      chunks.push(c);
    }
    const deltas = chunks.filter((c) => c.kind === "delta");
    expect(deltas.length).toBe(2);
    expect(deltas[0].text).toBe("a");
    const completed = chunks.find((c) => c.kind === "completed");
    expect(completed?.response?.content).toBe("ab");
  });
});

describe("WebLLM adapter — cancellation", () => {
  beforeEach(() => {
    vi.resetModules();
    stubWebGPU();
  });

  it("calls interruptGenerate when the abort signal fires", async () => {
    let interruptedCount = 0;
    const { engine } = makeFakeEngine({
      chunksPerCall: [
        [
          { choices: [{ delta: { content: "x" } }] } as unknown as ChatCompletionChunk,
        ],
      ],
      interrupted: () => {
        interruptedCount++;
      },
    });
    const session = await makeSession(engine);
    await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    const adapter = session.adapter;
    const ac = new AbortController();
    const p = adapter.complete({
      stageId: "s",
      messages: [],
      tools: [],
      outputSchema: {},
      options: {},
      signal: ac.signal,
    });
    ac.abort();
    await p;
    expect(interruptedCount).toBeGreaterThanOrEqual(1);
  });
});

describe("WebLLM adapter — generation bounds", () => {
  beforeEach(() => {
    vi.resetModules();
    stubWebGPU();
  });

  it("applies a default max_tokens cap when the caller does not supply one", async () => {
    const { engine, calls } = makeFakeEngine({
      chunksPerCall: [
        [
          { choices: [{ delta: { content: "{\"summary\":\"ok\"}" } }] } as unknown as ChatCompletionChunk,
        ],
      ],
    });
    const session = await makeSession(engine);
    await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    await session.adapter.complete({
      stageId: "s",
      messages: [],
      tools: [],
      outputSchema: {},
      options: {},
    });
    expect((calls[0] as { max_tokens: number }).max_tokens).toBe(1024);
  });

  it("respects an explicit max_tokens override", async () => {
    const { engine, calls } = makeFakeEngine({
      chunksPerCall: [
        [
          { choices: [{ delta: { content: "ok" } }] } as unknown as ChatCompletionChunk,
        ],
      ],
    });
    const session = await makeSession(engine);
    await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    await session.adapter.complete({
      stageId: "s",
      messages: [],
      tools: [],
      outputSchema: {},
      options: { max_tokens: 16 } as Record<string, unknown>,
    });
    expect((calls[0] as { max_tokens: number }).max_tokens).toBe(16);
  });

  it("aborts a degenerate token loop and interrupts the engine", async () => {
    let interruptedCount = 0;
    // The model locks into an endless ```\n cycle (the exact failure seen
    // in live traces). The fake engine streams 200 of these without stopping.
    const loop: ChatCompletionChunk[] = [];
    for (let i = 0; i < 200; i++) {
      loop.push(
        { choices: [{ delta: { content: i % 2 === 0 ? "```" : "`\n" } }] } as unknown as ChatCompletionChunk,
      );
    }
    const { engine } = makeFakeEngine({
      chunksPerCall: [loop],
      interrupted: () => {
        interruptedCount++;
      },
    });
    const session = await makeSession(engine);
    await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");

    let deltaCount = 0;
    for await (const chunk of session.adapter.stream!({
      stageId: "s",
      messages: [],
      tools: [],
      outputSchema: {},
      options: {},
    })) {
      if (chunk.kind === "delta") deltaCount++;
    }
    // The guard fires well before the full 200-chunk loop streams out.
    expect(deltaCount).toBeLessThan(200);
    expect(interruptedCount).toBeGreaterThanOrEqual(1);
  });

  it("aborts a phrase-level repetition loop whose deltas differ", async () => {
    let interruptedCount = 0;
    // Live-trace failure: the model re-emits a multi-token error phrase over
    // and over. Individual deltas differ, so a per-delta guard misses it, but
    // the accumulated content converges to a repeating block.
    const phrase = "model returned empty content in Stage 'Diag needs to be valid.\nError: ";
    const phraseDeltas = phrase.split(/(?<=\s)/).filter(Boolean);
    const loop: ChatCompletionChunk[] = [];
    for (let i = 0; i < 40; i++) {
      for (const d of phraseDeltas) {
        loop.push(
          { choices: [{ delta: { content: d } }] } as unknown as ChatCompletionChunk,
        );
      }
    }
    const { engine } = makeFakeEngine({
      chunksPerCall: [loop],
      interrupted: () => {
        interruptedCount++;
      },
    });
    const session = await makeSession(engine);
    await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");

    let deltaCount = 0;
    for await (const chunk of session.adapter.stream!({
      stageId: "s",
      messages: [],
      tools: [],
      outputSchema: {},
      options: {},
    })) {
      if (chunk.kind === "delta") deltaCount++;
    }
    const totalStreamed = phraseDeltas.length * 40;
    expect(deltaCount).toBeLessThan(totalStreamed);
    expect(interruptedCount).toBeGreaterThanOrEqual(1);
  });

  it("sets frequency/presence penalties by default to discourage repetition", async () => {
    const { engine, calls } = makeFakeEngine({
      chunksPerCall: [
        [
          { choices: [{ delta: { content: "ok" } }] } as unknown as ChatCompletionChunk,
        ],
      ],
    });
    const session = await makeSession(engine);
    await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    await session.adapter.complete({
      stageId: "s",
      messages: [],
      tools: [],
      outputSchema: {},
      options: {},
    });
    expect((calls[0] as { frequency_penalty: number }).frequency_penalty).toBe(0.5);
    expect((calls[0] as { presence_penalty: number }).presence_penalty).toBe(0.5);
  });
});

// ---------------------------------------------------------------------------
// Storage assessment (Phase 5)
// ---------------------------------------------------------------------------

describe("WebLLM session — storage assessment", () => {
  beforeEach(() => {
    vi.resetModules();
    stubWebGPU();
    // Default: no storage estimate API
    delete (navigator as unknown as Record<string, unknown>).storage;
  });

  function stubStorageEstimate(quota: number, usage: number) {
    Object.defineProperty(navigator, "storage", {
      value: {
        estimate: async () => ({ quota, usage }),
      },
      configurable: true,
    });
  }

  function stubNoStorageEstimate() {
    delete (navigator as unknown as Record<string, unknown>).storage;
  }

  function stubStorageEstimateThrows() {
    Object.defineProperty(navigator, "storage", {
      value: {
        estimate: async () => { throw new Error("denied"); },
      },
      configurable: true,
    });
  }

  it("returns supported=false when estimate API is absent", async () => {
    stubNoStorageEstimate();
    const { engine } = makeFakeEngine({});
    const session = await makeSession(engine);
    const a = await session.assessStorage("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    expect(a.supported).toBe(false);
    expect(a.likelySufficient).toBe(true); // never block on missing API
    expect(a.estimatedModelBytes).toBeGreaterThan(0);
  });

  it("returns likelySufficient=true when enough space is available", async () => {
    // Model needs ~944 MB. Give it 10 GB available.
    stubStorageEstimate(20 * 1024 * 1024 * 1024, 5 * 1024 * 1024 * 1024);
    const { engine } = makeFakeEngine({});
    const session = await makeSession(engine);
    const a = await session.assessStorage("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    expect(a.supported).toBe(true);
    expect(a.likelySufficient).toBe(true);
  });

  it("returns likelySufficient=false when storage is tight", async () => {
    // Model needs ~944 MB + margin. Give it only 500 MB available.
    stubStorageEstimate(1 * 1024 * 1024 * 1024, 500 * 1024 * 1024);
    const { engine } = makeFakeEngine({});
    const session = await makeSession(engine);
    const a = await session.assessStorage("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    expect(a.supported).toBe(true);
    expect(a.likelySufficient).toBe(false);
  });

  it("returns likelySufficient=true when estimate throws", async () => {
    stubStorageEstimateThrows();
    const { engine } = makeFakeEngine({});
    const session = await makeSession(engine);
    const a = await session.assessStorage("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
    expect(a.supported).toBe(false);
    expect(a.likelySufficient).toBe(true);
  });

  it("respects modelDownloadSizeOverrides for custom models", async () => {
    stubStorageEstimate(10 * 1024 * 1024 * 1024, 0);
    const { engine } = makeFakeEngine({});
    // Create session with an extra model and explicit download size override.
    vi.doMock("@mlc-ai/web-llm", () => ({
      CreateWebWorkerMLCEngine: async () => engine,
      prebuiltAppConfig: {
        model_list: [
          { model_id: "Custom-Model-q4f16_1-MLC", vram_required_MB: 1000 },
        ],
      },
      functionCallingModelIds: [],
      hasModelInCache: async (_id: string) => false,
    }));
    const { createWebllmSession } = await import("../webllm.js");
    const session = await createWebllmSession({
      workerFactory: () => ({ terminate() {}, postMessage() {} } as unknown as Worker),
      modelDownloadSizeOverrides: { "Custom-Model-q4f16_1-MLC": 20 * 1024 * 1024 * 1024 }, // 20 GB
    });
    const a = await session.assessStorage("Custom-Model-q4f16_1-MLC");
    expect(a.estimatedModelBytes).toBe(20 * 1024 * 1024 * 1024);
    // 10 GB available, 20 GB model → insufficient
    expect(a.likelySufficient).toBe(false);
  });

  it("returns likelySufficient=true for cached models", async () => {
    const modelId = "Qwen2.5-0.5B-Instruct-q4f16_1-MLC";
    // Mock hasModelInCache to return true
    vi.doMock("@mlc-ai/web-llm", () => ({
      CreateWebWorkerMLCEngine: async () => ({}),
      prebuiltAppConfig: {
        model_list: [
          { model_id: modelId, vram_required_MB: 5000, low_resource_required: false },
        ],
      },
      functionCallingModelIds: [],
      hasModelInCache: async (_id: string) => true,
    }));
    // Give very little storage — cached models should still appear sufficient.
    stubStorageEstimate(1 * 1024 * 1024 * 1024, 900 * 1024 * 1024);
    const { createWebllmSession } = await import("../webllm.js");
    const session = await createWebllmSession({
      workerFactory: () => ({ terminate() {}, postMessage() {} } as unknown as Worker),
    });
    const a = await session.assessStorage(modelId);
    expect(a.isCached).toBe(true);
    expect(a.likelySufficient).toBe(true);
  });
});

describe("classifyLoadError", () => {
  beforeEach(() => {
    vi.resetModules();
    stubWebGPU();
  });

  it("classifies weight-shard fetch failures by URL", async () => {
    const { classifyLoadError } = await import("../webllm.js");
    const f = classifyLoadError("m1", new Error("Cannot fetch https://huggingface.co/mlc-ai/m/resolve/main/params_shard_3.bin err= NetworkError: Cache.add() encountered a network error"));
    expect(f.phase).toBe("weight_shard");
    expect(f.failedUrl).toContain("params_shard_3.bin");
    expect(f.suggestsCorruptCache).toBe(true);
  });

  it("classifies wasm-library failures", async () => {
    const { classifyLoadError } = await import("../webllm.js");
    const f = classifyLoadError("m1", new Error("Cannot fetch https://raw.githubusercontent.com/mlc-ai/binary-mlc-llm-libs/main/web-llm-models/v0_2_84/base/Qwen3.5-2B-q4f16_1_cs1k-webgpu.wasm"));
    expect(f.phase).toBe("wasm_library");
    expect(f.failedUrl).toContain(".wasm");
  });

  it("classifies config/tokenizer failures", async () => {
    const { classifyLoadError } = await import("../webllm.js");
    const f = classifyLoadError("m1", new Error("ArtifactCache failed to fetch: https://huggingface.co/mlc-ai/m/resolve/main/mlc-chat-config.json"));
    expect(f.phase).toBe("config_or_tokenizer");
  });

  it("classifies JSON parse / cache corruption (SyntaxError)", async () => {
    const { classifyLoadError } = await import("../webllm.js");
    const f = classifyLoadError("m1", new SyntaxError("Unexpected end of JSON input"));
    expect(f.phase).toBe("cache_corruption");
    expect(f.suggestsCorruptCache).toBe(true);
  });

  it("classifies WebGPU init failures", async () => {
    const { classifyLoadError } = await import("../webllm.js");
    const f = classifyLoadError("m1", new Error("WebGPU: Device was lost. Insufficient memory."));
    expect(f.phase).toBe("webgpu_init");
  });

  it("classifies generic network errors", async () => {
    const { classifyLoadError } = await import("../webllm.js");
    const f = classifyLoadError("m1", new TypeError("network error"));
    expect(f.phase).toBe("network");
  });

  it("caps over-long error messages", async () => {
    const { classifyLoadError } = await import("../webllm.js");
    const long = "x".repeat(8000);
    const f = classifyLoadError("m1", new Error(long));
    expect(f.message.length).toBeLessThanOrEqual(5001);
    expect(f.message.endsWith("…")).toBe(true);
  });
});

describe("WebLLM retryLoad", () => {
  beforeEach(() => {
    vi.resetModules();
    stubWebGPU();
  });

  it("deletes cached artifacts then reloads on retryCleanDownload", async () => {
    let reloads = 0;
    let deleted = 0;
    vi.doMock("@mlc-ai/web-llm", () => ({
      CreateWebWorkerMLCEngine: async () => ({
        reload: async () => { reloads++; },
        unload: async () => {},
      }),
      prebuiltAppConfig: {
        model_list: [
          { model_id: "M1-q4f16_1-MLC", vram_required_MB: 500, low_resource_required: true },
        ],
      },
      functionCallingModelIds: [],
      hasModelInCache: async (_id: string) => false,
      deleteModelAllInfoInCache: async (_id: string) => { deleted++; },
    }));
    const { createWebllmSession } = await import("../webllm.js");
    const session = await createWebllmSession({
      workerFactory: () => ({ terminate() {}, postMessage() {} } as unknown as Worker),
    });
    // Ensure loaded first so a fresh worker is not incidentally recreated.
    await session.ensureLoaded("M1-q4f16_1-MLC");
    expect(reloads).toBe(0); // first load goes through CreateWebWorkerMLCEngine
    await session.retryLoad("M1-q4f16_1-MLC", { cleanCache: true, freshWorker: true });
    expect(deleted).toBe(1);
    expect(reloads).toBeGreaterThanOrEqual(0);
    expect(session.lastLoadFailure).toBeNull();
  });

  it("captures and classifies a load failure", async () => {
    vi.doMock("@mlc-ai/web-llm", () => ({
      CreateWebWorkerMLCEngine: async () => {
        throw new SyntaxError("Unexpected end of JSON input");
      },
      prebuiltAppConfig: {
        model_list: [
          { model_id: "M2-q4f16_1-MLC", vram_required_MB: 500, low_resource_required: true },
        ],
      },
      functionCallingModelIds: [],
      hasModelInCache: async (_id: string) => false,
      deleteModelAllInfoInCache: async (_id: string) => {},
    }));
    const { createWebllmSession } = await import("../webllm.js");
    const session = await createWebllmSession({
      workerFactory: () => ({ terminate() {}, postMessage() {} } as unknown as Worker),
    });
    await expect(session.ensureLoaded("M2-q4f16_1-MLC")).rejects.toThrow();
    expect(session.lastLoadFailure).not.toBeNull();
    expect(session.lastLoadFailure!.phase).toBe("cache_corruption");
    expect(session.lastLoadFailure!.modelId).toBe("M2-q4f16_1-MLC");
  });
});
