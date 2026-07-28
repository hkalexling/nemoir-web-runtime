/**
 * NemoIR Web Runtime — model-source profiles for WebLLM.
 *
 * A deployer who hosts their own mirrored MLC artifacts (e.g. on an
 * institutional CDN, Cloudflare R2, or S3-compatible object storage) can
 * declare them here and the tutor app will offer them as explicit model
 * sources alongside WebLLM's prebuilt Hugging Face records.
 *
 * Design:
 * - A `ModelSourceProfile` declares a named source (e.g. "Institutional CDN")
 *   and a list of `MirroredModelRecord`s, each of which points a logical
 *   `model_id` at mirror URLs for weights + WASM library.
 * - The `model_id` is made source-specific (e.g. `…-MLC` → `…-MLC@institution`)
 *   so a mirror and the upstream HF record never share a cache entry — a
 *   mixed cache from two different origins is a common source of corruption.
 * - `overlayModelRecords` merges prebuilt records with mirror records so the
 *   session's `AppConfig.model_list` sees both, and deduplicates by the
 *   source-specific `model_id`.
 * - Integrity (SRI) hashes are optional but recommended for mirror records.
 *
 * This is the *controlled-mirror* path only. Public mirrors (hf-mirror,
 * ModelScope, etc.) are intentionally not wired by default; they would be
 * declared as another `ModelSourceProfile` by a deployer who has verified
 * their artifact completeness, CORS/CORP headers, and serving correctness.
 */

import type { ModelRecord } from "@mlc-ai/web-llm";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A structural subset of WebLLM's `ModelRecord` sufficient to declare a
 * mirrored model. The base `model_id` is the logical id (without a source
 * suffix); the overlay assigns the source-specific id.
 */
export interface MirroredModelRecord {
  /** Logical model id (e.g. `"Llama-3.2-1B-Instruct-q4f16_1-MLC"`). */
  readonly baseModelId: string;
  /** Mirror URL for model weights/config/tokenizer (HF-style base URL). */
  readonly model: string;
  /** Mirror URL for the compiled WASM model library. */
  readonly modelLib: string;
  readonly vramRequiredMb?: number;
  readonly lowResourceRequired?: boolean;
  readonly requiredFeatures?: readonly string[];
  readonly overrides?: ModelRecord["overrides"];
  /**
   * Optional SRI integrity for the mirrored config, WASM, and tokenizer
   * files. Strongly recommended for third-party mirrors.
   */
  readonly integrity?: ModelRecord["integrity"];
}

export interface ModelSourceProfile {
  /** Display name, e.g. `"Institutional CDN"`. */
  readonly name: string;
  /** Short identifier used in the source-specific model_id suffix. */
  readonly sourceId: string;
  /** Mirrored model records available from this source. */
  readonly models: readonly MirroredModelRecord[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build the source-specific model id for a mirrored record.
 *
 * Example: `("Llama-3.2-1B-Instruct-q4f16_1-MLC", "institution")` →
 * `"Llama-3.2-1B-Instruct-q4f16_1-MLC@institution"`.
 */
export function mirrorModelId(baseModelId: string, sourceId: string): string {
  return `${baseModelId}@${sourceId}`;
}

/**
 * Convert a `MirroredModelRecord` + profile into a WebLLM `ModelRecord`
 * with a source-specific `model_id` and the mirror URLs.
 */
export function toMirroredModelRecord(
  mirror: MirroredModelRecord,
  profile: ModelSourceProfile,
): ModelRecord {
  return {
    model: mirror.model,
    model_id: mirrorModelId(mirror.baseModelId, profile.sourceId),
    model_lib: mirror.modelLib,
    overrides: mirror.overrides,
    vram_required_MB: mirror.vramRequiredMb,
    low_resource_required: mirror.lowResourceRequired,
    required_features: mirror.requiredFeatures
      ? [...mirror.requiredFeatures]
      : undefined,
    integrity: mirror.integrity,
  };
}

/**
 * Overlay one or more mirror profiles onto a list of prebuilt ModelRecords.
 *
 * The prebuilt records are kept as-is (their `model_id`s are un-suffixed).
 * Each mirlored record gets a source-specific `model_id` so it never collides
 * with a prebuilt record's cache entry. Duplicate source-specific ids within
 * the same profile set are deduplicated (last wins) to keep the manifest
 * stable.
 */
export function overlayModelRecords(
  prebuilt: readonly ModelRecord[],
  profiles: readonly ModelSourceProfile[],
): ModelRecord[] {
  const merged: ModelRecord[] = [...prebuilt];
  const seen = new Set(prebuilt.map((r) => r.model_id));

  for (const profile of profiles) {
    for (const mirror of profile.models) {
      const record = toMirroredModelRecord(mirror, profile);
      if (!seen.has(record.model_id)) {
        seen.add(record.model_id);
        merged.push(record);
      }
    }
  }

  return merged;
}
