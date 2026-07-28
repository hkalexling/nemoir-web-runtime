/**
 * Model-source profile tests.
 */

import { describe, it, expect } from "vitest";
import type { ModelRecord } from "@mlc-ai/web-llm";
import {
  mirrorModelId,
  toMirroredModelRecord,
  overlayModelRecords,
  type MirroredModelRecord,
  type ModelSourceProfile,
} from "../model-sources.js";

const prebuilt: ModelRecord[] = [
  {
    model: "https://huggingface.co/mlc-ai/Llama-3.2-1B-Instruct-q4f16_1-MLC",
    model_id: "Llama-3.2-1B-Instruct-q4f16_1-MLC",
    model_lib: "https://raw.githubusercontent.com/mlc-ai/binary-mlc-llm-libs/main/web-llm-models/v0_2_84/base/Llama-3.2-1B-Instruct-q4f16_1_cs1k-webgpu.wasm",
    vram_required_MB: 879.04,
  },
  {
    model: "https://huggingface.co/mlc-ai/Qwen3.5-2B-q4f16_1-MLC",
    model_id: "Qwen3.5-2B-q4f16_1-MLC",
    model_lib: "https://raw.githubusercontent.com/mlc-ai/binary-mlc-llm-libs/main/web-llm-models/v0_2_84/base/Qwen3.5-2B-q4f16_1_cs1k-webgpu.wasm",
    vram_required_MB: 2245.44,
  },
];

const cdnMirror: MirroredModelRecord = {
  baseModelId: "Llama-3.2-1B-Instruct-q4f16_1-MLC",
  model: "https://cdn.example.edu/models/mlc-ai/Llama-3.2-1B-Instruct-q4f16_1-MLC",
  modelLib: "https://cdn.example.edu/wasm/v0_2_84/base/Llama-3.2-1B-Instruct-q4f16_1_cs1k-webgpu.wasm",
  vramRequiredMb: 879.04,
  lowResourceRequired: true,
  requiredFeatures: ["shader-f16"],
};

const profile: ModelSourceProfile = {
  name: "Institutional CDN",
  sourceId: "institution",
  models: [cdnMirror],
};

describe("mirrorModelId", () => {
  it("suffixes the base id with the source id", () => {
    expect(mirrorModelId("Foo-MLC", "institution")).toBe("Foo-MLC@institution");
  });
});

describe("toMirroredModelRecord", () => {
  it("produces a source-specific model_id with mirror URLs", () => {
    const record = toMirroredModelRecord(cdnMirror, profile);
    expect(record.model_id).toBe("Llama-3.2-1B-Instruct-q4f16_1-MLC@institution");
    expect(record.model).toBe(cdnMirror.model);
    expect(record.model_lib).toBe(cdnMirror.modelLib);
    expect(record.vram_required_MB).toBe(879.04);
    expect(record.required_features).toEqual(["shader-f16"]);
  });
});

describe("overlayModelRecords", () => {
  it("appends mirrored records without touching prebuilt ids", () => {
    const merged = overlayModelRecords(prebuilt, [profile]);
    expect(merged.length).toBe(3);
    expect(merged.map((r) => r.model_id)).toContain("Llama-3.2-1B-Instruct-q4f16_1-MLC");
    expect(merged.map((r) => r.model_id)).toContain("Llama-3.2-1B-Instruct-q4f16_1-MLC@institution");
    expect(merged.map((r) => r.model_id)).toContain("Qwen3.5-2B-q4f16_1-MLC");
  });

  it("deduplicates mirror records with the same source-specific id", () => {
    const dupProfile: ModelSourceProfile = {
      ...profile,
      models: [cdnMirror, { ...cdnMirror, model: "https://other.example.edu/models/..." }],
    };
    const merged = overlayModelRecords(prebuilt, [dupProfile]);
    expect(merged.filter((r) => r.model_id === "Llama-3.2-1B-Instruct-q4f16_1-MLC@institution").length).toBe(1);
  });

  it("returns prebuilt unchanged when no profiles are given", () => {
    const merged = overlayModelRecords(prebuilt, []);
    expect(merged).toEqual(prebuilt);
  });

  it("supports multiple profiles with distinct source suffixes", () => {
    const profile2: ModelSourceProfile = {
      name: "Backup CDN",
      sourceId: "backup",
      models: [{
        ...cdnMirror,
        model: "https://backup.example.edu/models/...",
      }],
    };
    const merged = overlayModelRecords(prebuilt, [profile, profile2]);
    expect(merged.map((r) => r.model_id)).toContain("Llama-3.2-1B-Instruct-q4f16_1-MLC@institution");
    expect(merged.map((r) => r.model_id)).toContain("Llama-3.2-1B-Instruct-q4f16_1-MLC@backup");
  });
});
