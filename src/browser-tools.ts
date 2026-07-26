/**
 * NemoIR Web Runtime — browser-native tool implementations.
 *
 * Built-in tools for capabilities available on the web target:
 *   - `http.fetch` — browser fetch with structured result, cancellation,
 *     CORS-aware diagnostics, no hidden allowlist (policies govern authz).
 *   - `browser.storage.read` / `browser.storage.write` — workflow-namespaced
 *     IndexedDB store, separate from WebLLM's model cache.
 *   - `browser.js.run` — trusted deterministic-stage-only code execution in
 *     a fresh dedicated Web Worker. The worker receives JSON input and returns
 *     a JSON result; no DOM, no ambient workflow inputs. Timeout & cancellation
 *     terminate the worker. Only literal code is accepted by the compiler.
 *
 * These tools follow the same contract as all NemoIR tools: they enforce
 * input validity only; authorization is owned by NemoIR policies.
 */

import type { Tool } from "./tools.js";
import { isJsonSafeValue } from "./runtime.js";

// ---------------------------------------------------------------------------
// http.fetch
// ---------------------------------------------------------------------------

export interface HttpFetchResult {
  readonly ok: boolean;
  readonly status: number;
  readonly statusText: string;
  readonly headers: Record<string, string>;
  readonly body: { kind: "empty" } | { kind: "text"; text: string } | { kind: "json"; json: unknown };
}

async function httpFetchHandler(
  args: Record<string, unknown>,
  ctx: { signal?: AbortSignal },
): Promise<HttpFetchResult> {
  const url = args.url as string;
  const method = (args.method as string) ?? "GET";
  const headers = (args.headers as Record<string, string> | undefined) ?? {};
  const body = args.body as string | undefined;

  const requestHeaders = new Headers(headers);
  const init: RequestInit = {
    method,
    headers: requestHeaders,
    credentials: "omit",
    signal: ctx.signal,
  };

  if (body !== undefined && method !== "GET" && method !== "HEAD") {
    init.body = typeof body === "string" ? body : JSON.stringify(body);
    if (typeof body !== "string" && !requestHeaders.has("content-type")) {
      requestHeaders.set("content-type", "application/json");
    }
  }

  let response: Response;
  try {
    response = await fetch(url, init);
  } catch (e) {
    // Preserve AbortError for clean cancellation (check signal too for edge cases).
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    if (ctx.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    // Turn browser TypeError (network/CORS/CSP/COEP failures) into a
    // diagnostic that explains possible causes without pretending the
    // browser can identify the exact problem.
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(
      `http.fetch to ${url} failed: ${msg}. ` +
        `This may be caused by CORS restrictions, COEP policy, CSP ` +
        `connect-src rules, or a network error. ` +
        `Check the browser console for details.`,
    );
  }

  // Parse response body
  let bodyResult: HttpFetchResult["body"] = { kind: "empty" };
  const contentType = response.headers.get("content-type") ?? "";
  try {
    if (contentType.includes("application/json")) {
      const json = (await response.json()) as unknown;
      bodyResult = { kind: "json", json };
    } else {
      const text = await response.text();
      if (text.length > 0) {
        bodyResult = { kind: "text", text };
      }
    }
  } catch {
    // Body parsing failed — leave it as empty.
  }

  // Build header map (string-only values for simplicity)
  const headerMap: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headerMap[key] = value;
  });

  return {
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
    headers: headerMap,
    body: bodyResult,
  };
}

// ---------------------------------------------------------------------------
// browser.storage (IndexedDB, workflow-namespaced)
//
// Storage is workflow-key-namespaced by prefixing `${workflowId}::` onto
// each key. This is convenience isolation, NOT a security boundary:
// same-origin apps can access each other's data (IndexedDB is origin-scoped),
// and workflows with the same id silently share storage. For stronger
// isolation, deploy each workflow on a separate origin.
// ---------------------------------------------------------------------------

const DB_NAME = "nemoir-browser-storage";
const DB_VERSION = 1;
const STORE_NAME = "storage";

/** Open (or create) the indexeddb database once per process. */
let dbPromise: Promise<IDBDatabase> | null = null;

function getDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(new Error(`IndexedDB open failed: ${request.error?.message ?? "unknown"}`));
  });
  return dbPromise;
}

/** Build a workflow-namespaced key. */
function storageKey(workflowId: string, key: string): string {
  return `${workflowId}::${key}`;
}

async function storageReadHandler(
  args: Record<string, unknown>,
  ctx: { workflowId: string },
): Promise<{ key: string; found: boolean; value: unknown }> {
  const key = args.key as string;
  const db = await getDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(storageKey(ctx.workflowId, key));
    request.onsuccess = () => {
      const found = request.result !== undefined;
      resolve({
        key,
        found,
        value: found ? (request.result as { v: unknown }).v : null,
      });
    };
    request.onerror = () => reject(new Error(`storage read failed: ${request.error?.message}`));
  });
}

async function storageWriteHandler(
  args: Record<string, unknown>,
  ctx: { workflowId: string },
): Promise<{ key: string; written: boolean }> {
  const key = args.key as string;
  const value = args.value;
  // Enforce the JSON-safe contract at the tool boundary. IndexedDB's
  // structured-clone format would accept Map/Date/etc., which violate the
  // documented contract and would later fail stage-write validation;
  // reject them here so callers receive a clear, tool-local error.
  if (!isJsonSafeValue(value)) {
    throw new Error(
      `browser.storage.write value must be JSON-safe (plain objects, arrays, ` +
        `strings, finite numbers, booleans, null); got ${
          value === null ? "null" : typeof value === "object" ? Object.prototype.toString.call(value) : typeof value
        }`,
    );
  }
  const db = await getDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.put({ v: value }, storageKey(ctx.workflowId, key));
    request.onsuccess = () => resolve({ key, written: true });
    request.onerror = () => reject(new Error(`storage write failed: ${request.error?.message}`));
  });
}

// ---------------------------------------------------------------------------
// browser.js.run (trusted, deterministic-stage-only)
// ---------------------------------------------------------------------------

export interface JsRunOptions {
  /** Factory that creates a fresh Web Worker for each invocation. */
  readonly jsWorkerFactory: () => Worker;
  /** Timeout in ms after which the worker is terminated. Default 30_000. */
  readonly jsRunTimeoutMs?: number;
}

/**
 * Run trusted JS code in a fresh dedicated Web Worker.
 *
 * The worker receives `input` as a single JSON message and must post back a
 * single JSON message as the result. The worker is terminated on completion,
 * timeout, or cancellation.
 */
async function jsRunHandler(
  args: Record<string, unknown>,
  ctx: { signal?: AbortSignal },
  opts: JsRunOptions,
): Promise<Record<string, unknown>> {
  const code = args.code as string;
  const input = args.input;
  const timeoutMs = opts.jsRunTimeoutMs ?? 30000;

  // The jsWorkerFactory is required — `browser.js.run` tools are only
  // created when a factory is provided (see `createBrowserTools`).
  if (!opts.jsWorkerFactory) {
    throw new Error(
      "browser.js.run requires a jsWorkerFactory. Pass it via " +
        "BrowserToolsOptions when constructing the workflow agent.",
    );
  }
  const worker = opts.jsWorkerFactory();

  // Post the code and input to the worker for execution.
  worker.postMessage({ code, input });

  let rejectPromise: (reason: unknown) => void;

  const timeoutId = setTimeout(() => {
    worker.terminate();
    rejectPromise(new Error(`browser.js.run timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  const abortListener = () => {
    worker.terminate();
    rejectPromise(new DOMException("Cancelled by user", "AbortError"));
  };
  ctx.signal?.addEventListener("abort", abortListener, { once: true });

  try {
    const result = await new Promise<unknown>((resolve, reject) => {
      rejectPromise = reject;
      worker.onmessage = (e: MessageEvent) => {
        resolve(e.data);
      };
      worker.onerror = (e: ErrorEvent) => {
        reject(
          new Error(
            `browser.js.run worker error: ${e.message} (${e.filename}:${e.lineno})`,
          ),
        );
      };
      worker.onmessageerror = () => {
        reject(new Error("browser.js.run worker result is not structured-cloneable"));
      };
    });

    // Check for error wrapper from the worker
    if (typeof result === "object" && result !== null && "__error" in result) {
      throw new Error(`browser.js.run returned error: ${(result as { __error: string }).__error}`);
    }

    // Validate result is a plain JSON object. `isJsonSafeValue` rejects
    // Map, Date, class instances, cyclic structures (via JSON.stringify
    // impossibility is caught by structure-clone earlier), and non-plain
    // objects; the outer `typeof`/`Array.isArray` guards ensure the top level
    // is a plain object rather than a scalar or array.
    if (
      typeof result !== "object" ||
      result === null ||
      Array.isArray(result) ||
      !isJsonSafeValue(result)
    ) {
      throw new Error(
        `browser.js.run worker must return a plain JSON object; got ${
          result === null ? "null" : Array.isArray(result) ? "array" : typeof result === "object" ? Object.prototype.toString.call(result) : typeof result
        }`,
      );
    }

    return result as Record<string, unknown>;
  } finally {
    clearTimeout(timeoutId);
    ctx.signal?.removeEventListener("abort", abortListener);
    worker.terminate();
  }
}

// ---------------------------------------------------------------------------
// Tool factory
// ---------------------------------------------------------------------------

export interface BrowserToolsOptions {
  /** Required when the workflow uses `browser.js.run`. */
  readonly jsWorkerFactory?: () => Worker;
  /** Timeout for `browser.js.run` invocations. Default 30_000. */
  readonly jsRunTimeoutMs?: number;
}

/**
 * Create browser-native Tools for all web-target capabilities.
 *
 * Returns only the tools the caller opts into; workflows that do not
 * declare these capabilities pay nothing at construction.
 */
export function createBrowserTools(
  opts: BrowserToolsOptions,
): Tool[] {
  const tools: Tool[] = [];

  // http.fetch
  tools.push({
    name: "http_fetch",
    capability: "http.fetch",
    description:
      "Make an HTTP request from the browser. Returns status, headers, and a parsed body " +
      "(json if the response content-type is application/json, otherwise text).",
    inputSchema: {
      url: "string",
      method: "string",
      headers: "json",
      body: "json",
    },
    handler: async (args, ctx) => httpFetchHandler(args, ctx),
  });

  // browser.storage.read
  tools.push({
    name: "storage_read",
    capability: "browser.storage.read",
    description:
      "Read a value from the browser's workflow-scoped storage. " +
      "Returns { key, found, value } where found is false if the key does not exist.",
    inputSchema: { key: "string" },
    handler: async (args, ctx) => storageReadHandler(args, ctx),
  });

  // browser.storage.write
  tools.push({
    name: "storage_write",
    capability: "browser.storage.write",
    description:
      "Write a value to the browser's workflow-scoped storage. " +
      "Values must be JSON-safe (objects, arrays, strings, numbers, booleans, null). " +
      "Returns { key, written: true }.",
    inputSchema: { key: "string", value: "json" },
    handler: async (args, ctx) => storageWriteHandler(args, ctx),
  });

  // browser.js.run — only created when a worker factory is provided
  if (opts.jsWorkerFactory) {
    tools.push({
      name: "js_run",
      capability: "browser.js.run",
      description:
        "Execute trusted JavaScript in a fresh dedicated Web Worker. " +
        "The code receives `input` as its only argument and must return a plain JSON object. " +
        "Only available in deterministic (exec:) stages.",
      inputSchema: { code: "string", input: "json" },
      handler: async (args, ctx) =>
        jsRunHandler(args, ctx, {
          jsWorkerFactory: opts.jsWorkerFactory!,
          jsRunTimeoutMs: opts.jsRunTimeoutMs,
        }),
    });
  }

  return tools;
}
