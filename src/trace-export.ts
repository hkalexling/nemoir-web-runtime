/**
 * NemoIR Web Runtime — trace archive export helper.
 *
 * Turns a finished `.nemotrace` archive into a browser download. This is the
 * only supported way for a browser host to hand a trace to the user: it is
 * explicitly *user-gesture* driven (plan.md §5.2), writes no storage, and
 * never uploads anything. The bytes come from the recorder the host already
 * holds (`TraceRecorder.archiveBytes`); this module never creates, mutates,
 * or reads a trace itself.
 *
 * DOM access is injectable so the helper is unit-testable outside a browser
 * (JSON-schema-free, no global mutation) and so hosts with a non-standard
 * document (for example an embedded webview) can supply their own.
 */

/** Browser APIs used by {@link downloadTraceArchive}; injectable for tests. */
export interface TraceDownloadEnv {
  readonly document?: Document;
  readonly createObjectURL?: (blob: Blob) => string;
  readonly revokeObjectURL?: (url: string) => void;
}

const MEDIA_TYPE = "application/zip";

/** True when the download can run in the current environment. */
export function canDownloadTraceArchive(env: TraceDownloadEnv = {}): boolean {
  const doc = env.document ?? (typeof document === "undefined" ? undefined : document);
  if (doc === undefined) return false;
  const create = env.createObjectURL ?? createObjectURLFromGlobal();
  return typeof create === "function";
}

function createObjectURLFromGlobal(): ((blob: Blob) => string) | undefined {
  const url = (globalThis as { URL?: { createObjectURL?: (blob: Blob) => string } }).URL;
  return url?.createObjectURL === undefined ? undefined : url.createObjectURL.bind(url);
}

function revokeObjectURLFromGlobal(): ((url: string) => void) | undefined {
  const url = (globalThis as { URL?: { revokeObjectURL?: (url: string) => void } }).URL;
  return url?.revokeObjectURL === undefined ? undefined : url.revokeObjectURL.bind(url);
}

/**
 * Download a finished trace archive behind a user gesture.
 *
 * `filename` is suffixed with `.nemotrace` when it does not already carry
 * that extension. Throws a plain `Error` when the environment has no DOM —
 * callers should gate the export affordance on {@link canDownloadTraceArchive}
 * or on `recorder.archiveBytes !== null`.
 */
export function downloadTraceArchive(
  bytes: Uint8Array,
  filename: string,
  env: TraceDownloadEnv = {},
): void {
  const doc = env.document ?? (typeof document === "undefined" ? undefined : document);
  if (doc === undefined) {
    throw new Error("downloadTraceArchive requires a browser document");
  }
  const create = env.createObjectURL ?? createObjectURLFromGlobal();
  const revoke = env.revokeObjectURL ?? revokeObjectURLFromGlobal();
  if (create === undefined) {
    throw new Error("downloadTraceArchive requires URL.createObjectURL");
  }
  const name = filename.endsWith(".nemotrace") ? filename : `${filename}.nemotrace`;
  const blob = new Blob([bytes as unknown as BlobPart], { type: MEDIA_TYPE });
  const url = create(blob);
  try {
    const anchor = doc.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.rel = "noopener";
    doc.body.appendChild(anchor);
    try {
      anchor.click();
    } finally {
      anchor.remove();
    }
  } finally {
    // Revoke after the click has been dispatched; a microtask is enough for
    // the browser to capture the URL, and keeping it forever would leak.
    if (revoke !== undefined) queueMicrotask(() => revoke(url));
  }
}
