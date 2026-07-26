/**
 * Browser-native tools tests.
 *
 * Covers http.fetch, browser.storage.read/write, and browser.js.run
 * against mocked browser APIs (fetch, IndexedDB, Worker).
 *
 * Phase 6 exit criterion (§8 of docs/web-backend.md):
 *   - fetch cancellation/CORS failure
 *   - storage persistence / workflow-key namespacing
 *   - js.run result validation / timeout / cancellation
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createBrowserTools } from "../browser-tools.js";
import type { SandboxedJsRunner } from "../sandbox.js";
import type { Tool } from "../tools.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findTool(tools: Tool[], capability: string): Tool {
  const t = tools.find((t) => t.capability === capability);
  if (!t) throw new Error(`no tool for capability '${capability}'`);
  return t;
}

async function callTool(
  tool: Tool,
  args: Record<string, unknown>,
  ctx: { workflowId?: string; stageId?: string; signal?: AbortSignal } = {},
): Promise<unknown> {
  return tool.handler(args, {
    workflowId: ctx.workflowId ?? "test-wf",
    stageId: ctx.stageId ?? "test-stage",
    inputs: {},
    metadata: {},
    signal: ctx.signal,
  });
}

// ---------------------------------------------------------------------------
// http.fetch
// ---------------------------------------------------------------------------

describe("http.fetch", () => {
  let tools: Tool[];
  let fetchTool: Tool;

  beforeEach(() => {
    tools = createBrowserTools({});
    fetchTool = findTool(tools, "http.fetch");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns structured result for successful text response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("hello world", {
          status: 200,
          statusText: "OK",
          headers: { "content-type": "text/plain" },
        }),
      ),
    );

    const result = (await callTool(fetchTool, {
      url: "https://example.com",
      method: "GET",
    })) as Record<string, unknown>;

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.statusText).toBe("OK");
    expect((result.body as { kind: string; text: string }).kind).toBe("text");
    expect((result.body as { kind: string; text: string }).text).toBe(
      "hello world",
    );
  });

  it("returns structured result for JSON response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response('{"k":1}', {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    const result = (await callTool(fetchTool, {
      url: "https://api.example.com/data",
      method: "GET",
    })) as Record<string, unknown>;

    expect(result.ok).toBe(true);
    expect((result.body as { kind: string; json: unknown }).kind).toBe("json");
    expect(
      (result.body as { kind: string; json: Record<string, unknown> }).json,
    ).toEqual({ k: 1 });
  });

  it("returns result for non-2xx responses (does not throw)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("not found", {
          status: 404,
          statusText: "Not Found",
          headers: { "content-type": "text/plain" },
        }),
      ),
    );

    const result = (await callTool(fetchTool, {
      url: "https://example.com/missing",
      method: "GET",
    })) as Record<string, unknown>;

    expect(result.ok).toBe(false);
    expect(result.status).toBe(404);
    expect(result.statusText).toBe("Not Found");
  });

  it("throws diagnostic on network TypeError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("Failed to fetch")),
    );

    await expect(
      callTool(fetchTool, { url: "https://blocked.example.com", method: "GET" }),
    ).rejects.toThrow(/CORS/);
  });

  it("propagates AbortSignal to fetch", async () => {
    const fetchStub = vi.fn().mockResolvedValue(
      new Response("ok", { status: 200, headers: {} }),
    );
    vi.stubGlobal("fetch", fetchStub);

    const ac = new AbortController();
    ac.abort();

    await callTool(fetchTool, {
      url: "https://example.com",
      method: "GET",
    }, { signal: ac.signal });

    // Signal should have been passed to fetch init
    const init = fetchStub.mock.calls[0][1] as RequestInit;
    expect(init.signal?.aborted).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// In-memory IndexedDB shim for testing browser.storage
// ---------------------------------------------------------------------------

class InMemoryIDBDatabase {
  private readonly data = new Map<string, unknown>();
  readonly objectStoreNames = {
    _names: new Set<string>(),
    contains(name: string): boolean {
      return this._names.has(name);
    },
  };

  createObjectStore(name: string): void {
    (this.objectStoreNames._names as Set<string>).add(name);
  }

  transaction(_storeName: string, _mode: IDBTransactionMode) {
    const db = this;
    return {
      objectStore(_name: string) {
        return {
          get(key: string): { onsuccess?: () => void; onerror?: () => void; result?: unknown } {
            const request = {
              result: db.data.get(key),
              onsuccess: undefined as (() => void) | undefined,
              onerror: undefined as (() => void) | undefined,
            };
            queueMicrotask(() => {
              if (request.onsuccess) request.onsuccess();
            });
            return request;
          },
          put(value: unknown, key: string): { onsuccess?: () => void; onerror?: () => void; result?: unknown } {
            db.data.set(key, value);
            const request = {
              result: key,
              onsuccess: undefined as (() => void) | undefined,
              onerror: undefined as (() => void) | undefined,
            };
            queueMicrotask(() => {
              if (request.onsuccess) request.onsuccess();
            });
            return request;
          },
        };
      },
    } as unknown as IDBTransaction;
  }

  close() {
    // no-op — in-memory DB is reset per test
  }
}

function stubIndexedDB(
  db: InMemoryIDBDatabase,
): void {
  const idbFactory: Record<string, unknown> = {
    _db: db,
    open(_name: string, _version?: number) {
      const request = {
        result: db as unknown as IDBDatabase,
        onsuccess: undefined as (() => void) | undefined,
        onerror: undefined as (() => void) | undefined,
        onupgradeneeded: undefined as (() => void) | undefined,
        error: null as Error | null,
      };
      queueMicrotask(() => {
        // Fire onupgradeneeded first (simulate new DB), then onsuccess
        if (request.onupgradeneeded) request.onupgradeneeded();
        if (request.onsuccess) request.onsuccess();
      });
      return request as unknown as IDBOpenDBRequest;
    },
  };
  vi.stubGlobal("indexedDB", idbFactory);
}

// ---------------------------------------------------------------------------
// browser.storage
// ---------------------------------------------------------------------------

describe("browser.storage", () => {
  let tools: Tool[];
  let readTool: Tool;
  let writeTool: Tool;
  let db: InMemoryIDBDatabase;

  beforeEach(async () => {
    // Reset the module to clear the cached dbPromise from browser-tools.ts
    vi.resetModules();
    const mod = await import("../browser-tools.js");
    db = new InMemoryIDBDatabase();
    stubIndexedDB(db);
    tools = mod.createBrowserTools({});
    readTool = findTool(tools, "browser.storage.read");
    writeTool = findTool(tools, "browser.storage.write");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("read returns { found: false } for unknown key", async () => {
    const result = (await callTool(readTool, { key: "unknown" })) as Record<
      string,
      unknown
    >;
    expect(result.found).toBe(false);
    expect(result.key).toBe("unknown");
    expect(result.value).toBeNull();
  });

  it("write then read round-trips a value", async () => {
    await callTool(writeTool, { key: "mykey", value: { n: 42, s: "hi" } });
    const result = (await callTool(readTool, { key: "mykey" })) as Record<
      string,
      unknown
    >;
    expect(result.found).toBe(true);
    expect(result.key).toBe("mykey");
    expect((result.value as Record<string, unknown>).n).toBe(42);
    expect((result.value as Record<string, unknown>).s).toBe("hi");
  });

  it("workflow-key namespacing: different workflows have separate storage", async () => {
    // Write under workflow "A"
    await callTool(writeTool, { key: "shared", value: "from-a" }, {
      workflowId: "A",
    });
    // Read under workflow "B" — should miss
    const resultB = (await callTool(readTool, { key: "shared" }, {
      workflowId: "B",
    })) as Record<string, unknown>;
    expect(resultB.found).toBe(false);

    // Read under workflow "A" — should hit
    const resultA = (await callTool(readTool, { key: "shared" }, {
      workflowId: "A",
    })) as Record<string, unknown>;
    expect(resultA.found).toBe(true);
    expect(resultA.value).toBe("from-a");
  });
});

// ---------------------------------------------------------------------------
// browser.storage.write JSON-safe contract (Medium #1)
// ---------------------------------------------------------------------------

describe("browser.storage.write JSON-safe contract", () => {
  let writeTool: Tool;
  let db: InMemoryIDBDatabase;

  beforeEach(async () => {
    db = new InMemoryIDBDatabase();
    stubIndexedDB(db);
    const mod = await import("../browser-tools.js");
    const tools = mod.createBrowserTools({});
    writeTool = findTool(tools, "browser.storage.write");
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects a Map value before touching IndexedDB", async () => {
    await expect(
      callTool(writeTool, { key: "m", value: new Map([["k", 1]]) }),
    ).rejects.toThrow(/JSON-safe/);
  });

  it("rejects a Date value", async () => {
    await expect(
      callTool(writeTool, { key: "d", value: new Date() }),
    ).rejects.toThrow(/JSON-safe/);
  });

  it("rejects a cyclic value", async () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    await expect(
      callTool(writeTool, { key: "c", value: cyclic }),
    ).rejects.toThrow(/JSON-safe/);
  });
});

// A reusable stub Worker matching the handler's listener contract.
function makeWorkerStub() {
  return {
    _listeners: {} as Record<string, (e: unknown) => void>,
    postMessage(_msg: unknown) {},
    terminate() {},
    set onmessage(fn: (e: unknown) => void) {
      this._listeners.message = fn;
    },
    set onerror(_fn: (e: unknown) => void) {},
    set onmessageerror(_fn: () => void) {},
    addEventListener(_type: string, _fn: unknown) {},
    removeEventListener(_type: string, _fn: unknown) {},
  };
}

// ---------------------------------------------------------------------------
// browser.js.run
// ---------------------------------------------------------------------------

describe("browser.js.run", () => {
  it("returns valid object result from worker", async () => {
    const workerStub = {
      _listeners: {} as Record<string, (e: unknown) => void>,
      postMessage(_msg: unknown) {},
      terminate() {},
      set onmessage(fn: (e: unknown) => void) {
        this._listeners.message = fn;
      },
      set onerror(_fn: (e: unknown) => void) {},
      set onmessageerror(_fn: () => void) {},
      addEventListener(_type: string, _fn: unknown) {},
      removeEventListener(_type: string, _fn: unknown) {},
    };

    const tools = createBrowserTools({
      jsWorkerFactory: () => workerStub as unknown as Worker,
    });
    const jsRunTool = findTool(tools, "browser.js.run");

    // Simulate the worker posting back a valid object
    const resultPromise = callTool(jsRunTool, {
      code: "return { n: 42 }",
      input: { x: 1 },
    });
    queueMicrotask(() => {
      workerStub._listeners.message({ data: { n: 42 } });
    });

    const result = (await resultPromise) as Record<string, unknown>;
    expect(result.n).toBe(42);
  });

  it("throws on non-object worker result", async () => {
    const workerStub = {
      _listeners: {} as Record<string, (e: unknown) => void>,
      postMessage(_msg: unknown) {},
      terminate() {},
      set onmessage(fn: (e: unknown) => void) {
        this._listeners.message = fn;
      },
      set onerror(_fn: (e: unknown) => void) {},
      set onmessageerror(_fn: () => void) {},
      addEventListener(_type: string, _fn: unknown) {},
      removeEventListener(_type: string, _fn: unknown) {},
    };

    const tools = createBrowserTools({
      jsWorkerFactory: () => workerStub as unknown as Worker,
    });
    const jsRunTool = findTool(tools, "browser.js.run");

    const resultPromise = callTool(jsRunTool, {
      code: "return 'string'",
      input: {},
    });
    queueMicrotask(() => {
      workerStub._listeners.message({ data: "not an object" });
    });

    await expect(resultPromise).rejects.toThrow(/plain JSON object/);
  });

  it("terminates worker on timeout", async () => {
    let terminated = false;
    const workerStub = {
      _listeners: {} as Record<string, (e: unknown) => void>,
      postMessage(_msg: unknown) {},
      terminate() {
        terminated = true;
      },
      set onmessage(_fn: (e: unknown) => void) {},
      set onerror(_fn: (e: unknown) => void) {},
      set onmessageerror(_fn: () => void) {},
      addEventListener(_type: string, _fn: unknown) {},
      removeEventListener(_type: string, _fn: unknown) {},
    };

    const tools = createBrowserTools({
      jsWorkerFactory: () => workerStub as unknown as Worker,
      jsRunTimeoutMs: 10,
    });
    const jsRunTool = findTool(tools, "browser.js.run");

    // Worker never responds — timeout should fire and reject
    await expect(callTool(jsRunTool, {
      code: "while(true) {}",
      input: {},
    })).rejects.toThrow(/timed out/);
    expect(terminated).toBe(true);
  });

  it("terminates worker on AbortSignal cancellation", async () => {
    let terminated = false;
    const workerStub = {
      _listeners: {} as Record<string, (e: unknown) => void>,
      postMessage(_msg: unknown) {},
      terminate() {
        terminated = true;
      },
      set onmessage(_fn: (e: unknown) => void) {},
      set onerror(_fn: (e: unknown) => void) {},
      set onmessageerror(_fn: () => void) {},
      addEventListener(_type: string, _fn: unknown) {},
      removeEventListener(_type: string, _fn: unknown) {},
    };

    const tools = createBrowserTools({
      jsWorkerFactory: () => workerStub as unknown as Worker,
    });
    const jsRunTool = findTool(tools, "browser.js.run");

    const ac = new AbortController();
    const resultPromise = callTool(
      jsRunTool,
      { code: "while(true) {}", input: {} },
      { signal: ac.signal },
    );

    // Abort — the abort listener in jsRunHandler should terminate and reject
    ac.abort();
    await expect(resultPromise).rejects.toThrow("Cancelled by user");
    expect(terminated).toBe(true);
  });

  it("rejects a Map worker result", async () => {
    const workerStub = makeWorkerStub();
    const tools = createBrowserTools({
      jsWorkerFactory: () => workerStub as unknown as Worker,
    });
    const jsRunTool = findTool(tools, "browser.js.run");

    const resultPromise = callTool(jsRunTool, { code: "return new Map()", input: {} });
    queueMicrotask(() => {
      workerStub._listeners.message({
        data: new Map([["result", 42]]),
      });
    });
    await expect(resultPromise).rejects.toThrow(/plain JSON object/);
  });

  it("rejects a Date worker result", async () => {
  const workerStub = makeWorkerStub();
    const tools = createBrowserTools({
      jsWorkerFactory: () => workerStub as unknown as Worker,
    });
    const jsRunTool = findTool(tools, "browser.js.run");

    const resultPromise = callTool(jsRunTool, { code: "return new Date()", input: {} });
    queueMicrotask(() => {
      workerStub._listeners.message({ data: new Date() });
    });
    await expect(resultPromise).rejects.toThrow(/plain JSON object/);
  });

  it("handles the generated worker's `{ __error }` thrown-code protocol", async () => {
    // Exercises the real `src/js.worker.ts` protocol: when the trusted code
    // throws, the worker posts back `{ __error: <message> }` and the host
    // re-throws it as an Error. This covers Medium #3 #2 (protocol parity
    // with the generated worker) without requiring a real browser worker.
    const workerStub = makeWorkerStub();
    const tools = createBrowserTools({
      jsWorkerFactory: () => workerStub as unknown as Worker,
    });
    const jsRunTool = findTool(tools, "browser.js.run");

    const resultPromise = callTool(jsRunTool, {
      code: "throw new Error('boom')",
      input: {},
    });
    queueMicrotask(() => {
      workerStub._listeners.message({ data: { __error: "boom" } });
    });
    await expect(resultPromise).rejects.toThrow(/browser.js.run returned error: boom/);
  });

  it("throws if jsWorkerFactory is not provided", () => {
    const tools = createBrowserTools({});
    const jsRunTool = tools.find((t) => t.capability === "browser.js.run");
    // No jsWorkerFactory → no js.run tool should be created
    expect(jsRunTool).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// browser.js.sandbox
// ---------------------------------------------------------------------------

describe("browser.js.sandbox", () => {
  it("forwards dynamic source and JSON input to the configured opaque-origin runner", async () => {
    const runner: SandboxedJsRunner = {
      run: vi.fn().mockResolvedValue({ result: 42 }),
    };
    const tools = createBrowserTools({
      jsSandboxRunner: runner,
      jsSandboxTimeoutMs: 321,
      jsSandboxMaxCodeBytes: 123,
      jsSandboxMaxInputBytes: 456,
      jsSandboxMaxOutputBytes: 789,
    });
    const sandboxTool = findTool(tools, "browser.js.sandbox");

    await expect(callTool(sandboxTool, {
      code: "return { result: input.x + 1 };",
      input: { x: 41 },
    })).resolves.toEqual({ result: 42 });

    expect(runner.run).toHaveBeenCalledWith(expect.objectContaining({
      code: "return { result: input.x + 1 };",
      input: { x: 41 },
      timeoutMs: 321,
      maxCodeBytes: 123,
      maxInputBytes: 456,
      maxOutputBytes: 789,
    }));
  });

  it("rejects a non-string source before invoking the runner", async () => {
    const runner: SandboxedJsRunner = { run: vi.fn() };
    const sandboxTool = findTool(
      createBrowserTools({ jsSandboxRunner: runner }),
      "browser.js.sandbox",
    );

    await expect(callTool(sandboxTool, { code: { not: "code" }, input: {} }))
      .rejects.toThrow("code must be a string");
    expect(runner.run).not.toHaveBeenCalled();
  });

  it("is not registered without an explicit sandbox runner", () => {
    const tools = createBrowserTools({});
    expect(tools.find((t) => t.capability === "browser.js.sandbox")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// http.fetch deny-policy enforcement (Medium #3 #4)
// ---------------------------------------------------------------------------

describe("http.fetch deny-policy enforcement", () => {
  it("does not call fetch when a deny policy blocks the URL", async () => {
    // A deterministic http.fetch stage with a deny policy whose condition
    // matches the request URL. The fetch handler must never be invoked.
    const { WorkflowAgent } = await import("../agent.js");
    const { createBrowserTools } = await import("../browser-tools.js");
    const { PolicyDeniedError } = await import("../errors.js");

    const fetchSpy = vi.fn().mockResolvedValue(
      new Response("ok", { status: 200, headers: { "content-type": "text/plain" } }),
    );
    vi.stubGlobal("fetch", fetchSpy);

    const ir = {
      ir_version: "0.1",
      kind: "workflow_ir",
      source: { frontend: "test", file: "test.nemo" },
      workflow: {
        id: "FetchDeny",
        entry: "Fetch",
        exits: ["Fetch"],
        transition_semantics: { selection: "first_match_by_priority", no_match: "error_unless_exit" },
      },
      inputs: [],
      capabilities: ["http.fetch"],
      policies: [{
        id: "deny http.fetch to blocked.example",
        kind: "deny",
        trigger: { capability: "http.fetch", bind: { url: { kind: "arg", name: "url" } } },
        // url starts with the blocked origin → truthy → denied
        condition: {
          kind: "method_call",
          receiver: { kind: "ref", ref: { kind: "bound", name: "url" } },
          method: "starts_with",
          args: [{ kind: "literal", type: "string", value: "https://blocked.example.com" }],
        },
      }],
      nodes: [{
        id: "Fetch",
        annotations: ["entry", "exit"],
        prompt: "",
        reads: [],
        writes: [
          { name: "ok", type: "bool", optional: false },
          { name: "status", type: "number", optional: false },
        ],
        requires: [{ capability: "http.fetch" }],
        transitions: [],
        execution: {
          kind: "tool",
          capability: "http.fetch",
          args: {
            url: { kind: "literal", type: "string", value: "https://blocked.example.com/secret" },
            method: { kind: "literal", type: "string", value: "GET" },
          },
        },
      }],
    };

    const agent = new WorkflowAgent(ir, {
      tools: createBrowserTools({}),
    });

    await expect(agent.run({})).rejects.toThrow(PolicyDeniedError);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
