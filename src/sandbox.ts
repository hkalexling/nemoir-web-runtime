/**
 * Opaque-origin dynamic JavaScript sandbox for NemoIR's web target.
 *
 * This is deliberately separate from the trusted `browser.js.run` worker.
 * Dynamic source is run in a fresh Worker owned by a sandboxed iframe with a
 * unique opaque origin. The iframe has no `allow-same-origin` token and its
 * CSP blocks network, frames, forms, media, storage-bearing same-origin
 * access, and browser permissions. The parent and iframe communicate only
 * over a transferred MessagePort; the user program never receives that port.
 *
 * This is a browser isolation boundary, not a defence against browser-engine
 * vulnerabilities or resource exhaustion. The host still terminates the
 * entire iframe on timeout/cancellation and never gives the sandbox ambient
 * NemoIR tools or host objects.
 */

import { isJsonSafeValue } from "./runtime.js";

export const DEFAULT_JS_SANDBOX_TIMEOUT_MS = 5_000;
export const DEFAULT_JS_SANDBOX_MAX_CODE_BYTES = 64 * 1024;
export const DEFAULT_JS_SANDBOX_MAX_INPUT_BYTES = 256 * 1024;
export const DEFAULT_JS_SANDBOX_MAX_OUTPUT_BYTES = 256 * 1024;

/**
 * CSP applied inside the opaque-origin iframe. Dynamic code runs in a nested
 * Worker, so there is no DOM. `unsafe-eval` is intentionally scoped to this
 * isolated document/Worker because the Worker uses `new Function` to execute
 * the supplied source; it is never enabled in the host document.
 */
export const OPAQUE_ORIGIN_SANDBOX_CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "child-src 'none'",
  "connect-src 'none'",
  "font-src 'none'",
  "form-action 'none'",
  "frame-src 'none'",
  "img-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "script-src 'unsafe-inline' 'unsafe-eval' blob:",
  "style-src 'none'",
  "worker-src blob:",
].join("; ");

export interface JsSandboxRequest {
  readonly code: string;
  readonly input: unknown;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  readonly maxCodeBytes?: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}

/** A pluggable execution boundary used by the `browser.js.sandbox` tool. */
export interface SandboxedJsRunner {
  run(request: JsSandboxRequest): Promise<Record<string, unknown>>;
}

export interface OpaqueOriginJsSandboxOptions {
  /**
   * Optional document injection for nonstandard hosts and tests. Omit this in
   * a browser to use the ambient document lazily at construction time.
   */
  readonly document?: Document;
  readonly timeoutMs?: number;
  readonly maxCodeBytes?: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}

interface SandboxMessage {
  readonly type: string;
  readonly result?: unknown;
  readonly error?: unknown;
}

const SANDBOX_READY = "nemoir-js-sandbox-ready";
const SANDBOX_RUN = "nemoir-js-sandbox-run";
const SANDBOX_RESULT = "nemoir-js-sandbox-result";
const SANDBOX_ERROR = "nemoir-js-sandbox-error";
const SANDBOX_INIT = "nemoir-js-sandbox-init";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function abortError(): DOMException {
  return new DOMException("Cancelled by user", "AbortError");
}

function resolvePositiveLimit(
  value: number | undefined,
  fallback: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return resolved;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

/**
 * Non-allocating UTF-8 byte counter.
 *
 * Avoids creating an encoded copy of an arbitrarily large untrusted source
 * string before a configured byte-limit gate rejects it. Walks the string via
 * the 16-bit code units and accounts for the UTF-8 expansion of code points
 * above U+007F.
 */
export function utf8ByteLength(s: string): number {
  let bytes = 0;
  for (let i = 0; i < s.length; i++) {
    let code = s.charCodeAt(i);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate; combine with the following low surrogate to form a
      // 4-byte UTF-8 code point. Lone surrogates are counted as 3 bytes.
      const next = s.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function jsonByteLength(value: unknown): number {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new Error("browser.js.sandbox value is not JSON-serializable");
  }
  return byteLength(serialized);
}

function validatePlainJsonObject(value: unknown, maxOutputBytes: number): Record<string, unknown> {
  if (
    !isRecord(value) ||
    !isJsonSafeValue(value)
  ) {
    throw new Error(
      "browser.js.sandbox must return a plain JSON object",
    );
  }
  if (jsonByteLength(value) > maxOutputBytes) {
    throw new Error(
      `browser.js.sandbox result exceeds ${maxOutputBytes} byte limit`,
    );
  }
  return value;
}

/**
 * Static worker source. It receives an unexposed reply port, so dynamic code
 * cannot spoof messages accepted by the host. Calls to the Worker's default
 * `postMessage` are intentionally ignored by the iframe runner.
 */
export const SANDBOX_WORKER_SOURCE = String.raw`
self.onmessage = async (event) => {
  const request = event.data;
  const replyPort = event.ports && event.ports[0];
  if (!replyPort || !request || request.type !== "${SANDBOX_RUN}" || typeof request.code !== "string") {
    return;
  }
  try {
    // CSP is the browser enforcement boundary. Shadow common networking and
    // worker-spawning globals as a second layer so dynamic code has no easy
    // ambient escape hatch even on browsers with uneven CSP coverage.
    const disabled = () => {
      throw new Error("Network and worker creation are disabled in browser.js.sandbox");
    };
    for (const name of [
      "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "WebTransport",
      "RTCPeerConnection", "importScripts", "Worker", "SharedWorker",
    ]) {
      try {
        Object.defineProperty(self, name, {
          value: disabled,
          writable: false,
          configurable: false,
        });
      } catch (_) {
        // A browser can expose an immutable or absent global; CSP remains the
        // mandatory boundary for that API.
      }
    }
    const fn = new (Object.getPrototypeOf(async function(){}).constructor)(
      "input",
      '"use strict";\n' + request.code
    );
    const result = await fn(request.input);
    replyPort.postMessage({ type: "${SANDBOX_RESULT}", result });
  } catch (error) {
    replyPort.postMessage({
      type: "${SANDBOX_ERROR}",
      error: error instanceof Error ? error.message : String(error),
    });
  }
};
`;

/**
 * Static, user-data-free iframe document. Source and input travel over a
 * private MessageChannel only after the opaque-origin frame has loaded, so a
 * user string can never break out of `srcdoc` markup or this bootstrap.
 */
export const OPAQUE_ORIGIN_SANDBOX_DOCUMENT = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="${OPAQUE_ORIGIN_SANDBOX_CSP}">
</head>
<body>
<script>
(() => {
  const WORKER_SOURCE = ${JSON.stringify(SANDBOX_WORKER_SOURCE)};
  let hostPort = null;

  const send = (message) => {
    if (hostPort) hostPort.postMessage(message);
  };

  const execute = (request) => {
    let worker = null;
    let url = null;
    let resultPort = null;
    let settled = false;

    const finish = (message) => {
      if (settled) return;
      settled = true;
      if (resultPort) resultPort.close();
      if (worker) worker.terminate();
      if (url) URL.revokeObjectURL(url);
      send(message);
    };

    try {
      const blob = new Blob([WORKER_SOURCE], { type: "text/javascript" });
      url = URL.createObjectURL(blob);
      worker = new Worker(url);
      const channel = new MessageChannel();
      resultPort = channel.port1;
      resultPort.onmessage = (event) => finish(event.data);
      resultPort.onmessageerror = () => finish({
        type: "${SANDBOX_ERROR}",
        error: "sandbox worker result is not structured-cloneable",
      });
      resultPort.start && resultPort.start();
      worker.onerror = (event) => finish({
        type: "${SANDBOX_ERROR}",
        error: event && event.message ? event.message : "sandbox worker error",
      });
      worker.onmessageerror = () => finish({
        type: "${SANDBOX_ERROR}",
        error: "sandbox worker request is not structured-cloneable",
      });
      worker.postMessage({
        type: "${SANDBOX_RUN}",
        code: request.code,
        input: request.input,
      }, [channel.port2]);
    } catch (error) {
      finish({
        type: "${SANDBOX_ERROR}",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  };

  window.addEventListener("message", (event) => {
    if (!event.data || event.data.type !== "${SANDBOX_INIT}" || hostPort || !event.ports || event.ports.length !== 1) {
      return;
    }
    hostPort = event.ports[0];
    hostPort.onmessage = (portEvent) => {
      const request = portEvent.data;
      if (!request || request.type !== "${SANDBOX_RUN}") return;
      execute(request);
    };
    hostPort.start && hostPort.start();
    send({ type: "${SANDBOX_READY}" });
  });
})();
</script>
</body>
</html>`;

/**
 * A browser-native dynamic-code runner with an opaque-origin iframe boundary.
 * Constructing it has no side effects; a fresh iframe and nested Worker are
 * created for each run and removed on every terminal path.
 */
export class OpaqueOriginJsSandbox implements SandboxedJsRunner {
  private readonly document: Document | undefined;
  private readonly timeoutMs: number;
  private readonly maxCodeBytes: number;
  private readonly maxInputBytes: number;
  private readonly maxOutputBytes: number;

  constructor(opts: OpaqueOriginJsSandboxOptions = {}) {
    this.document = opts.document ?? (typeof document === "undefined" ? undefined : document);
    this.timeoutMs = resolvePositiveLimit(
      opts.timeoutMs,
      DEFAULT_JS_SANDBOX_TIMEOUT_MS,
      "js sandbox timeoutMs",
    );
    this.maxCodeBytes = resolvePositiveLimit(
      opts.maxCodeBytes,
      DEFAULT_JS_SANDBOX_MAX_CODE_BYTES,
      "js sandbox maxCodeBytes",
    );
    this.maxInputBytes = resolvePositiveLimit(
      opts.maxInputBytes,
      DEFAULT_JS_SANDBOX_MAX_INPUT_BYTES,
      "js sandbox maxInputBytes",
    );
    this.maxOutputBytes = resolvePositiveLimit(
      opts.maxOutputBytes,
      DEFAULT_JS_SANDBOX_MAX_OUTPUT_BYTES,
      "js sandbox maxOutputBytes",
    );
  }

  async run(request: JsSandboxRequest): Promise<Record<string, unknown>> {
    if (typeof request.code !== "string") {
      throw new Error("browser.js.sandbox code must be a string");
    }
    if (!isJsonSafeValue(request.input)) {
      throw new Error("browser.js.sandbox input must be JSON-safe");
    }

    const timeoutMs = resolvePositiveLimit(
      request.timeoutMs,
      this.timeoutMs,
      "js sandbox timeoutMs",
    );
    const maxCodeBytes = resolvePositiveLimit(
      request.maxCodeBytes,
      this.maxCodeBytes,
      "js sandbox maxCodeBytes",
    );
    const maxInputBytes = resolvePositiveLimit(
      request.maxInputBytes,
      this.maxInputBytes,
      "js sandbox maxInputBytes",
    );
    const maxOutputBytes = resolvePositiveLimit(
      request.maxOutputBytes,
      this.maxOutputBytes,
      "js sandbox maxOutputBytes",
    );

    if (byteLength(request.code) > maxCodeBytes) {
      throw new Error(`browser.js.sandbox code exceeds ${maxCodeBytes} byte limit`);
    }
    if (jsonByteLength(request.input) > maxInputBytes) {
      throw new Error(`browser.js.sandbox input exceeds ${maxInputBytes} byte limit`);
    }
    if (request.signal?.aborted) {
      throw abortError();
    }

    const doc = this.document;
    if (!doc) {
      throw new Error("browser.js.sandbox requires a browser Document");
    }
    if (typeof MessageChannel === "undefined") {
      throw new Error("browser.js.sandbox requires MessageChannel support");
    }

    return new Promise<Record<string, unknown>>((resolve, reject) => {
      const frame = doc.createElement("iframe");
      const mount = doc.body ?? doc.documentElement;
      if (!mount) {
        reject(new Error("browser.js.sandbox requires a document root"));
        return;
      }

      let settled = false;
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      const channel = new MessageChannel();
      const hostPort = channel.port1;

      const cleanup = () => {
        if (timeoutId !== undefined) clearTimeout(timeoutId);
        request.signal?.removeEventListener("abort", onAbort);
        hostPort.onmessage = null;
        hostPort.close();
        frame.remove();
      };
      const fail = (error: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      };
      const succeed = (result: Record<string, unknown>) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(result);
      };
      const onAbort = () => fail(abortError());

      frame.setAttribute("sandbox", "allow-scripts");
      frame.setAttribute("aria-hidden", "true");
      frame.setAttribute("tabindex", "-1");
      frame.allow = [
        "camera 'none'",
        "clipboard-read 'none'",
        "clipboard-write 'none'",
        "display-capture 'none'",
        "geolocation 'none'",
        "microphone 'none'",
        "payment 'none'",
        "serial 'none'",
        "usb 'none'",
      ].join("; ");
      frame.referrerPolicy = "no-referrer";
      frame.style.display = "none";
      frame.srcdoc = OPAQUE_ORIGIN_SANDBOX_DOCUMENT;

      hostPort.onmessage = (event: MessageEvent<SandboxMessage>) => {
        const message = event.data;
        if (!message || typeof message.type !== "string") return;
        if (message.type === SANDBOX_READY) {
          hostPort.postMessage({
            type: SANDBOX_RUN,
            code: request.code,
            input: request.input,
          });
          return;
        }
        if (message.type === SANDBOX_RESULT) {
          try {
            succeed(validatePlainJsonObject(message.result, maxOutputBytes));
          } catch (error) {
            fail(error);
          }
          return;
        }
        if (message.type === SANDBOX_ERROR) {
          fail(new Error(`browser.js.sandbox returned error: ${String(message.error ?? "unknown error")}`));
        }
      };
      hostPort.start();

      frame.addEventListener("load", () => {
        const contentWindow = frame.contentWindow;
        if (!contentWindow) {
          fail(new Error("browser.js.sandbox iframe did not expose a contentWindow"));
          return;
        }
        // An opaque origin cannot be targeted by a concrete origin string;
        // authentication comes from the private transferred port, not `*`.
        contentWindow.postMessage({ type: SANDBOX_INIT }, "*", [channel.port2]);
      }, { once: true });
      frame.addEventListener("error", () => {
        fail(new Error("browser.js.sandbox iframe failed to load"));
      }, { once: true });

      timeoutId = setTimeout(() => {
        fail(new Error(`browser.js.sandbox timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      request.signal?.addEventListener("abort", onAbort, { once: true });
      mount.appendChild(frame);
    });
  }
}

/** Create the standard browser-native opaque-origin sandbox runner. */
export function createOpaqueOriginJsSandbox(
  opts: OpaqueOriginJsSandboxOptions = {},
): SandboxedJsRunner {
  return new OpaqueOriginJsSandbox(opts);
}
