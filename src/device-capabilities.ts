/**
 * NemoIR Web Runtime — WebGPU device-capability detection + model fit.
 *
 * Framework-neutral. Used to classify which WebLLM models are likely to run
 * on the current device so the UI can recommend models first and warn on
 * underpowered / oversized selections without forcing a multi-GB download to
 * discover a failure.
 */

import type { WebLlmModelInfo } from "./webllm.js";

// ---------------------------------------------------------------------------
// Device capabilities
// ---------------------------------------------------------------------------

export interface WebGpuCapabilityReport {
  /** True when `navigator.gpu` exists at all. */
  readonly available: boolean;
  /** Adapter vendor / description from `requestAdapterInfo()`, when known. */
  readonly adapterInfo: string | null;
  /**
   * True when the adapter exposes `shader-f16` (required by `q4f16_1` models).
   * Null when the probe failed or WebGPU is unavailable.
   */
  readonly shaderF16Supported: boolean | null;
  /**
   * `maxStorageBufferBindingSize` limit in bytes, when known. Models with a
   * `buffer_size_required_bytes` above this cannot run.
   */
  readonly maxStorageBufferBindingSize: number | null;
  /** True when the probe itself threw (best-effort detection). */
  readonly probeError: boolean;
}

export interface DeviceStorageReport {
  readonly supported: boolean;
  readonly quota: number | null;
  readonly usage: number | null;
  readonly available: number | null;
}

export interface DeviceCapabilityReport {
  readonly webgpu: WebGpuCapabilityReport;
  readonly storage: DeviceStorageReport;
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

/**
 * Probe the current device's WebGPU + storage capabilities.
 *
 * This is best-effort: any failure degrades to `null` so callers never block
 * on a missing API. Safe to call repeatedly.
 */
export async function probeDeviceCapabilities(): Promise<DeviceCapabilityReport> {
  return {
    webgpu: await probeWebGpu(),
    storage: await probeStorage(),
  };
}

async function probeWebGpu(): Promise<WebGpuCapabilityReport> {
  const nav = navigator as Navigator & { gpu?: unknown };
  if (typeof navigator === "undefined" || typeof nav.gpu !== "object" || nav.gpu === null) {
    return {
      available: false,
      adapterInfo: null,
      shaderF16Supported: null,
      maxStorageBufferBindingSize: null,
      probeError: false,
    };
  }
  try {
    const gpu = nav.gpu as {
      requestAdapter?: () => Promise<{
        requestAdapterInfo?: () => Promise<{ vendor?: string; description?: string }>;
        features?: { has: (f: string) => boolean };
        requestDevice: () => Promise<{ limits: { maxStorageBufferBindingSize: number }; destroy: () => void }>;
      } | null>;
    };
    if (typeof gpu.requestAdapter !== "function") throw new Error("requestAdapter unavailable");
    const adapter = await gpu.requestAdapter();
    if (!adapter) {
      return {
        available: false,
        adapterInfo: null,
        shaderF16Supported: null,
        maxStorageBufferBindingSize: null,
        probeError: false,
      };
    }
    let adapterInfo: string | null = null;
    let shaderF16Supported: boolean | null = null;
    let maxStorageBufferBindingSize: number | null = null;

    // `requestAdapterInfo` is optional in some browsers; guard it.
    const requestAdapterInfo = (
      adapter as unknown as { requestAdapterInfo?: () => Promise<{ vendor?: string; description?: string }> }
    ).requestAdapterInfo;
    if (typeof requestAdapterInfo === "function") {
      try {
        const info = await requestAdapterInfo.call(adapter);
        adapterInfo = [info.description, info.vendor].filter(Boolean).join(" — ") || null;
      } catch {
        // Leave null.
      }
    }

    try {
      if (adapter.features) shaderF16Supported = adapter.features.has("shader-f16");
    } catch {
      // Leave null.
    }

    try {
      const device = await adapter.requestDevice();
      maxStorageBufferBindingSize = device.limits.maxStorageBufferBindingSize;
      device.destroy();
    } catch {
      // Some adapters are present but cannot create a device; downgrade
      // gracefully without crashing the catalog.
    }

    return {
      available: true,
      adapterInfo,
      shaderF16Supported,
      maxStorageBufferBindingSize,
      probeError: false,
    };
  } catch {
    return {
      available: true,
      adapterInfo: null,
      shaderF16Supported: null,
      maxStorageBufferBindingSize: null,
      probeError: true,
    };
  }
}

async function probeStorage(): Promise<DeviceStorageReport> {
  try {
    if (
      typeof navigator !== "undefined" &&
      typeof navigator.storage === "object" &&
      navigator.storage !== null &&
      typeof (navigator.storage as { estimate?: unknown }).estimate === "function"
    ) {
      const est = await navigator.storage.estimate();
      if (est && typeof est.quota === "number" && typeof est.usage === "number") {
        return {
          supported: true,
          quota: est.quota,
          usage: est.usage,
          available: Math.max(0, est.quota - est.usage),
        };
      }
    }
  } catch {
    // estimate() may throw (opaque origins etc.).
  }
  return { supported: false, quota: null, usage: null, available: null };
}

// ---------------------------------------------------------------------------
// Model fit classification
// ---------------------------------------------------------------------------

export type ModelFitCategory =
  | "recommended"
  | "likely_ok"
  | "needs_download"
  | "oversized_vram"
  | "missing_feature"
  | "buffer_limit"
  | "unknown";

export interface ModelFitAssessment {
  readonly modelId: string;
  readonly category: ModelFitCategory;
  /**
   * True when the model is cached (no download required), which overrides
   * download-size concerns but not VRAM/feature limits.
   */
  readonly isCached: boolean;
  /** Human-readable summary for display. */
  readonly message: string;
}

/** Default 1GB VRAM threshold for "small/local" models; only a UI heuristic. */
export const SMALL_MODEL_VRAM_MB = 2048;

/**
 * Classify how well a model fits the current device.
 *
 * Recommendations are intentionally conservative: we never *block* a load
 * (the learner may know more than our heuristic), we only order and annotate.
 */
export function assessModelFit(
  model: WebLlmModelInfo,
  device: DeviceCapabilityReport,
  opts: {
    readonly isCached: boolean;
    readonly estimatedDownloadBytes?: number;
  },
): ModelFitAssessment {
  const { isCached, estimatedDownloadBytes } = opts;
  const vramMb = model.vramRequiredMb ?? 0;

  // --- Hard blockers first (cached or not, these cannot run) ---
  if (model.requiredFeatures && model.requiredFeatures.length > 0) {
    for (const feature of model.requiredFeatures) {
      if (feature === "shader-f16" && device.webgpu.shaderF16Supported === false) {
        return {
          modelId: model.modelId,
          category: "missing_feature",
          isCached,
          message: "Requires shader-f16, which this GPU does not support.",
        };
      }
    }
  }

  if (vramMb > 0 && device.webgpu.shaderF16Supported !== null) {
    // We can't read exact VRAM from the WebGPU adapter, but very large models
    // on a software renderer (SwiftShader) are almost always OOMs.
    const isSoftwareRenderer = device.webgpu.adapterInfo?.toLowerCase().includes("swiftshader") ?? false;
    if (isSoftwareRenderer && vramMb > 2048) {
      return {
        modelId: model.modelId,
        category: "oversized_vram",
        isCached,
        message: `${gbLabel(vramMb)} on a software renderer (no dedicated GPU) is very likely to run out of memory.`,
      };
    }
  }

  // --- Download/size heuristics for uncached models ---
  if (!isCached) {
    if (device.storage.supported && device.storage.available !== null && estimatedDownloadBytes) {
      const margin = Math.max(512 * 1024 * 1024, Math.round(estimatedDownloadBytes * 0.2));
      if (estimatedDownloadBytes + margin > device.storage.available) {
        return {
          modelId: model.modelId,
          category: "oversized_vram",
          isCached,
          message: `~${gbLabel(estimatedDownloadBytes / (1024 * 1024))} download; browser storage may be insufficient.`,
        };
      }
    }
    if (estimatedDownloadBytes && estimatedDownloadBytes > 4 * 1024 * 1024 * 1024) {
      return {
        modelId: model.modelId,
        category: "needs_download",
        isCached,
        message: `Large ~${gbLabel(estimatedDownloadBytes / (1024 * 1024))} download; pick a smaller model for a faster first load.`,
      };
    }
  }

  // --- Positive recommendations ---
  if (model.lowResourceRequired && vramMb > 0 && vramMb <= SMALL_MODEL_VRAM_MB) {
    return {
      modelId: model.modelId,
      category: "recommended",
      isCached,
      message: isCached
        ? "Cached and lightweight; recommended for this device."
        : "Lightweight; recommended first model for a quick local download.",
    };
  }

  if (vramMb > 0 && vramMb <= SMALL_MODEL_VRAM_MB) {
    return {
      modelId: model.modelId,
      category: "likely_ok",
      isCached,
      message: isCached
        ? "Cached; should run on modest hardware."
        : "Small model; should run on modest hardware.",
    };
  }

  if (isCached) {
    return {
      modelId: model.modelId,
      category: "likely_ok",
      isCached,
      message: "Cached; ready to load without a download.",
    };
  }

  if (vramMb > 8 * 1024) {
    return {
      modelId: model.modelId,
      category: "needs_download",
      isCached,
      message: `Very large (~${gbLabel(vramMb)} VRAM); likely needs a discrete GPU.`,
    };
  }

  return {
    modelId: model.modelId,
    category: "unknown",
    isCached,
    message: isCached ? "Cached." : "Download required.",
  };
}

function gbLabel(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${Math.round(mb)} MB`;
}
