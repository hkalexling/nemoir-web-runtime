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
