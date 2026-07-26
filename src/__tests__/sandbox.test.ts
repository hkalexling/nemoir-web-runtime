/** Tests for the opaque-origin dynamic-code sandbox contract.
 *
 * Note (coverage gap): these tests assert static CSP/bootstrap strings and
 * fail-closed behavior outside a browser. They do NOT mount the opaque-origin
 * iframe, transfer ports, run dynamic code in the nested Worker, verify CSP
 * enforcement, or verify iframe cleanup on timeout/cancellation in a real
 * browser. That browser integration coverage is deferred — see
 * `docs/web-backend.md` §14 “Deferred work”. When a browser integration test
 * harness (e.g. Playwright) is added, add assertions there for: successful
 * JSON execution after approval, no host DOM/parent access, blocked
 * network/worker-spawn attempts, timeout/cancellation cleanup, and zero
 * remaining sandbox iframes.
 */

import { describe, expect, it } from "vitest";
import {
  DEFAULT_JS_SANDBOX_MAX_CODE_BYTES,
  OPAQUE_ORIGIN_SANDBOX_CSP,
  OPAQUE_ORIGIN_SANDBOX_DOCUMENT,
  OpaqueOriginJsSandbox,
} from "../sandbox.js";

describe("OpaqueOriginJsSandbox", () => {
  it("keeps the restrictive CSP inside a static, user-data-free iframe bootstrap", () => {
    expect(OPAQUE_ORIGIN_SANDBOX_CSP).toContain("default-src 'none'");
    expect(OPAQUE_ORIGIN_SANDBOX_CSP).toContain("connect-src 'none'");
    expect(OPAQUE_ORIGIN_SANDBOX_CSP).toContain("worker-src blob:");
    expect(OPAQUE_ORIGIN_SANDBOX_DOCUMENT).toContain("Content-Security-Policy");
    expect(OPAQUE_ORIGIN_SANDBOX_DOCUMENT).toContain("new Worker(url)");
    expect(OPAQUE_ORIGIN_SANDBOX_DOCUMENT).toContain("fetch");
    expect(OPAQUE_ORIGIN_SANDBOX_DOCUMENT).toContain("RTCPeerConnection");
    expect(OPAQUE_ORIGIN_SANDBOX_DOCUMENT).toContain('async function');
    expect(OPAQUE_ORIGIN_SANDBOX_DOCUMENT).toContain('Object.getPrototypeOf(async function');
    expect(OPAQUE_ORIGIN_SANDBOX_DOCUMENT).toContain("MessageChannel");
  });

  it("rejects oversized dynamic source before creating a browser sandbox", async () => {
    const runner = new OpaqueOriginJsSandbox({ document: undefined });
    await expect(runner.run({
      code: "x".repeat(DEFAULT_JS_SANDBOX_MAX_CODE_BYTES + 1),
      input: {},
    })).rejects.toThrow("code exceeds");
  });

  it("rejects non-JSON-safe input before creating a browser sandbox", async () => {
    const runner = new OpaqueOriginJsSandbox({ document: undefined });
    await expect(runner.run({
      code: "return { ok: true };",
      input: new Date(),
    })).rejects.toThrow("input must be JSON-safe");
  });

  it("fails closed when called outside a browser document", async () => {
    const runner = new OpaqueOriginJsSandbox({ document: undefined });
    await expect(runner.run({
      code: "return { ok: true };",
      input: {},
    })).rejects.toThrow("requires a browser Document");
  });
});

// ---------------------------------------------------------------------------
// Async-function-constructor execution model (mirrors the worker source)
// ---------------------------------------------------------------------------

describe("sandbox async function constructor", () => {
  // Replicates the worker's execution boundary: an async function constructed
  // so top-level `await` and returned Promises are both supported.
  async function runInSandboxModel(code: string, input: unknown): Promise<unknown> {
    const fn = new (Object.getPrototypeOf(async function () {}).constructor)(
      "input",
      '"use strict";\n' + code,
    );
    return fn(input);
  }

  it("supports top-level await in the source body", async () => {
    const result = await runInSandboxModel(
      "const value = await Promise.resolve(input.x + 1); return { result: value };",
      { x: 41 },
    );
    expect(result).toEqual({ result: 42 });
  });

  it("supports returning a Promise (async IIFE) in the source body", async () => {
    const result = await runInSandboxModel(
      "return (async () => ({ result: await Promise.resolve(input.x * 2) }))();",
      { x: 21 },
    );
    expect(result).toEqual({ result: 42 });
  });

  it("supports synchronous returns", async () => {
    const result = await runInSandboxModel(
      "return { result: input.x };",
      { x: 42 },
    );
    expect(result).toEqual({ result: 42 });
  });
});
