/**
 * Trace archive export helper: user-gesture `.nemotrace` download.
 *
 * The helper must be inert outside a browser (JSON-safe, no global mutation),
 * must name the file correctly, and must never leave a live object URL.
 */

import { describe, expect, it, vi } from "vitest";

import {
  canDownloadTraceArchive,
  downloadTraceArchive,
  type TraceDownloadEnv,
} from "../trace-export.js";

interface AnchorLike {
  href: string;
  download: string;
  rel: string;
  click: () => void;
  remove: () => void;
}

function fakeEnv(): {
  readonly env: TraceDownloadEnv;
  readonly anchors: AnchorLike[];
  readonly revoked: string[];
  readonly blobs: Blob[];
} {
  const anchors: AnchorLike[] = [];
  const revoked: string[] = [];
  const blobs: Blob[] = [];
  const env: TraceDownloadEnv = {
    document: {
      createElement: () => {
        const anchor: AnchorLike = {
          href: "",
          download: "",
          rel: "",
          click: () => undefined,
          remove: () => undefined,
        };
        anchors.push(anchor);
        return anchor as unknown as HTMLElement;
      },
      body: { appendChild: () => undefined },
    } as unknown as Document,
    createObjectURL: (blob: Blob) => {
      blobs.push(blob);
      return "blob:trace";
    },
    revokeObjectURL: (url: string) => {
      revoked.push(url);
    },
  };
  return { env, anchors, revoked, blobs };
}

describe("trace export", () => {
  it("reports availability from the environment", () => {
    expect(canDownloadTraceArchive(fakeEnv().env)).toBe(true);
    expect(canDownloadTraceArchive({ document: undefined, createObjectURL: undefined })).toBe(false);
  });

  it("downloads bytes with a .nemotrace filename behind a click", async () => {
    const { env, anchors, revoked, blobs } = fakeEnv();
    const bytes = new Uint8Array([1, 2, 3, 4]);
    downloadTraceArchive(bytes, "workflow-trace", env);
    expect(blobs).toHaveLength(1);
    expect(blobs[0]!.type).toBe("application/zip");
    expect((await blobs[0]!.arrayBuffer()).byteLength).toBe(4);
    expect(anchors).toHaveLength(1);
    expect(anchors[0]!.download).toBe("workflow-trace.nemotrace");
    expect(anchors[0]!.href).toBe("blob:trace");
    expect(anchors[0]!.rel).toBe("noopener");
    await Promise.resolve();
    expect(revoked).toEqual(["blob:trace"]);
  });

  it("does not double-append the extension", () => {
    const { env, anchors, revoked } = fakeEnv();
    downloadTraceArchive(new Uint8Array(0), "trace.nemotrace", env);
    expect(anchors[0]!.download).toBe("trace.nemotrace");
    expect(revoked).toEqual([]); // revoked on a microtask, not synchronously
  });

  it("fails closed without a document or object URLs", () => {
    expect(() =>
      downloadTraceArchive(new Uint8Array(0), "trace.nemotrace", { document: undefined }),
    ).toThrow(/requires a browser document/);
    const { env } = fakeEnv();
    const realCreate = globalThis.URL.createObjectURL;
    // Node has no `URL.createObjectURL` for Blob in every version; if it does,
    // this branch is unreachable and the assertion is skipped.
    if (realCreate === undefined) {
      expect(() =>
        downloadTraceArchive(new Uint8Array(0), "trace.nemotrace", {
          document: env.document,
          createObjectURL: undefined,
        }),
      ).toThrow(/requires URL.createObjectURL/);
    }
  });

  it("revokes the URL even when the click throws", async () => {
    const { env, anchors, revoked } = fakeEnv();
    const revokeSpy = vi.fn((url: string) => revoked.push(url));
    anchors.length = 0;
    const failing = {
      ...env,
      document: {
        createElement: () => {
          const anchor = {
            href: "",
            download: "",
            rel: "",
            click: () => {
              throw new Error("blocked");
            },
            remove: () => undefined,
          };
          anchors.push(anchor);
          return anchor as unknown as HTMLElement;
        },
        body: { appendChild: () => undefined },
      } as unknown as Document,
      revokeObjectURL: revokeSpy,
    };
    expect(() => downloadTraceArchive(new Uint8Array(0), "t.nemotrace", failing)).toThrow("blocked");
    await Promise.resolve();
    expect(revokeSpy).toHaveBeenCalledWith("blob:trace");
  });
});
