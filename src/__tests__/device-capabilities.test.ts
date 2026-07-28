/**
 * Device-capability + model-fit assessment tests.
 */

import { describe, it, expect } from "vitest";
import {
  assessModelFit,
  SMALL_MODEL_VRAM_MB,
  type DeviceCapabilityReport,
} from "../device-capabilities.js";
import type { WebLlmModelInfo } from "../webllm.js";

function mkModel(overrides: Partial<WebLlmModelInfo> = {}): WebLlmModelInfo {
  return {
    modelId: "Test-Model-q4f16_1-MLC",
    label: "Test Model",
    vramRequiredMb: 944,
    lowResourceRequired: true,
    ...overrides,
  };
}

const goodDevice: DeviceCapabilityReport = {
  webgpu: {
    available: true,
    adapterInfo: "Apple M2",
    shaderF16Supported: true,
    maxStorageBufferBindingSize: 1 << 30,
    probeError: false,
  },
  storage: {
    supported: true,
    quota: 20 * 1024 * 1024 * 1024,
    usage: 2 * 1024 * 1024 * 1024,
    available: 18 * 1024 * 1024 * 1024,
  },
};

describe("assessModelFit", () => {
  it("recommends a small uncached model", () => {
    const r = assessModelFit(mkModel(), goodDevice, {
      isCached: false,
      estimatedDownloadBytes: 944 * 1024 * 1024,
    });
    expect(r.category).toBe("recommended");
    expect(r.isCached).toBe(false);
  });

  it("recommends a cached lightweight model", () => {
    const r = assessModelFit(mkModel(), goodDevice, {
      isCached: true,
      estimatedDownloadBytes: 944 * 1024 * 1024,
    });
    expect(r.category).toBe("recommended");
    expect(r.isCached).toBe(true);
    expect(r.message).toContain("Cached");
  });

  it("flags missing shader-f16 as a hard blocker", () => {
    const deviceNoF16: DeviceCapabilityReport = {
      ...goodDevice,
      webgpu: { ...goodDevice.webgpu, shaderF16Supported: false },
    };
    const r = assessModelFit(
      mkModel({ requiredFeatures: ["shader-f16"], vramRequiredMb: 500, lowResourceRequired: true }),
      deviceNoF16,
      { isCached: false, estimatedDownloadBytes: 500 * 1024 * 1024 },
    );
    expect(r.category).toBe("missing_feature");
    expect(r.message).toContain("shader-f16");
  });

  it("flags oversized VRAM on a software renderer", () => {
    const deviceSwift: DeviceCapabilityReport = {
      ...goodDevice,
      webgpu: { ...goodDevice.webgpu, adapterInfo: "SwiftShader" },
    };
    const r = assessModelFit(
      mkModel({ vramRequiredMb: 4096, lowResourceRequired: false }),
      deviceSwift,
      { isCached: false, estimatedDownloadBytes: 4 * 1024 * 1024 * 1024 },
    );
    expect(r.category).toBe("oversized_vram");
    expect(r.message).toContain("software renderer");
  });

  it("flags large downloads over 4GB", () => {
    const r = assessModelFit(
      mkModel({ vramRequiredMb: 4096, lowResourceRequired: false }),
      goodDevice,
      { isCached: false, estimatedDownloadBytes: 4.5 * 1024 * 1024 * 1024 },
    );
    expect(r.category).toBe("needs_download");
    expect(r.message).toContain("Large");
  });

  it("flags oversized download when storage is low", () => {
    const deviceLowStorage: DeviceCapabilityReport = {
      ...goodDevice,
      storage: {
        supported: true,
        quota: 5 * 1024 * 1024 * 1024,
        usage: 4.8 * 1024 * 1024 * 1024,
        available: 0.2 * 1024 * 1024 * 1024, // 200 MB free
      },
    };
    const r = assessModelFit(
      mkModel({ vramRequiredMb: 500, lowResourceRequired: true }),
      deviceLowStorage,
      { isCached: false, estimatedDownloadBytes: 500 * 1024 * 1024 },
    );
    // Small model + low resource, but only 200MB free → storage insufficient
    expect(r.category).toBe("oversized_vram");
    expect(r.message).toContain("storage");
  });

  it("recommends models at or below the small-model threshold", () => {
    expect(SMALL_MODEL_VRAM_MB).toBeGreaterThan(0);
    const r = assessModelFit(
      mkModel({ vramRequiredMb: SMALL_MODEL_VRAM_MB, lowResourceRequired: true }),
      goodDevice,
      { isCached: false, estimatedDownloadBytes: SMALL_MODEL_VRAM_MB * 1024 * 1024 },
    );
    expect(r.category).toBe("recommended");
  });

  it("classifies cached large models as likely_ok (no download concern)", () => {
    const r = assessModelFit(
      mkModel({ vramRequiredMb: 5120, lowResourceRequired: false }),
      goodDevice,
      { isCached: true, estimatedDownloadBytes: 5 * 1024 * 1024 * 1024 },
    );
    expect(r.category).toBe("likely_ok");
    expect(r.message).toContain("Cached");
  });
});
