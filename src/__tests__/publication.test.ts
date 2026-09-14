/**
 * Phase 5 publication transform: projection, attestation, and refusals.
 *
 * These tests assert the frozen vectors in the vendored
 * `test-vectors/schema/test-vectors/publication/` byte for byte, so the Python
 * and TypeScript transformers provably agree on every logical artifact (the
 * ZIP container differs by DEFLATE implementation and is never compared).
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { VECTORS_ROOT } from "./vectors.js";

import { parseJsonStrict, sha256Tag, toCanonicalBytes } from "../canonical.js";
import {
  attestationDocument,
  attestationFromDict,
  attestationFromReport,
  publicationReport,
  scanPublication,
  serializeDocument,
  type PublicationProjection,
} from "../publication.js";
import { readArchiveEntries, verifyArchive, writeArchive } from "../trace.js";

const VECTORS = VECTORS_ROOT;
const PUBLICATION = join(VECTORS, "publication");
const SOURCE_PATH = join(PUBLICATION, "source.nemotrace");
const SOURCE_BYTES = new Uint8Array(readFileSync(SOURCE_PATH));
const SOURCE_NAME = "source.nemotrace";
const CONSENT =
  "I reviewed the disclosure report and certify this trace is safe to publish.";
const REVIEWED_AT = "2026-09-12T00:00:00.000Z";

function vector(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(PUBLICATION, name)));
}

function vectorJson(name: string): Record<string, unknown> {
  return parseJsonStrict(new TextDecoder().decode(vector(name))) as Record<string, unknown>;
}

/**
 * Rebuild the frozen source with mutated ledger records and a fresh integrity
 * index, so a test can prove the scanner gate blocks a leak that already sits
 * in a source archive.
 */
async function rebuildSource(
  mutate: (events: Record<string, Record<string, unknown>>) => void,
): Promise<Uint8Array> {
  const entries = readArchiveEntries(SOURCE_BYTES);
  const decoder = new TextDecoder();
  const events: Record<string, Record<string, unknown>> = {};
  decoder
    .decode(entries["public/events.ndjson"]!)
    .split("\n")
    .forEach((line, index) => {
      if (line.trim() !== "") events[String(index)] = parseJsonStrict(line) as Record<string, unknown>;
    });
  mutate(events);
  const ordered = Object.keys(events)
    .map((key) => Number(key))
    .sort((a, b) => a - b)
    .map((index) => events[String(index)]!);
  const newline = new TextEncoder().encode("\n");
  const chunks = ordered.flatMap((record) => [toCanonicalBytes(record), newline]);
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const ledger = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    ledger.set(chunk, offset);
    offset += chunk.length;
  }
  const payloads: Record<string, Uint8Array> = { ...entries, "public/events.ndjson": ledger };
  delete payloads["integrity.json"];
  const index: Record<string, unknown>[] = [];
  for (const path of Object.keys(payloads).sort()) {
    const data = payloads[path]!;
    index.push({
      path,
      media_type: path.endsWith(".ndjson") ? "application/x-ndjson" : "application/json",
      uncompressed_bytes: data.length,
      sha256: await sha256Tag(data),
    });
  }
  const identity = {
    format: "nemoir.trace.content-identity/0.1",
    entries: index.map(({ path, sha256, uncompressed_bytes }) => ({ path, sha256, uncompressed_bytes })),
  };
  payloads["integrity.json"] = toCanonicalBytes({
    format: "nemoir.trace.integrity/0.1",
    algorithm: "sha256",
    entries: index,
    content_identity: await sha256Tag(toCanonicalBytes(identity)),
  });
  return writeArchive(payloads);
}

function scan(options = {}): Promise<PublicationProjection> {
  return scanPublication(SOURCE_PATH, SOURCE_BYTES, options, SOURCE_NAME);
}

describe("publication frozen vectors", () => {
  it("projects entries byte-identical to the frozen vectors", async () => {
    const projection = await scan();
    for (const [frozen, entry] of [
      ["expected-manifest.json", "manifest.json"],
      ["expected-graph.json", "public/workflow.graph.json"],
      ["expected-ledger.ndjson", "public/events.ndjson"],
      ["expected-summary.json", "public/summary.json"],
      ["expected-integrity.json", "integrity.json"],
    ] as const) {
      expect(projection.entries[entry]).toEqual(vector(frozen));
    }
  });

  it("matches frozen digests, identity, and stats", async () => {
    const frozen = vectorJson("expected-digests.json");
    const projection = await scan();
    expect(projection.projection_sha256).toBe(frozen["projection_sha256"]);
    expect(projection.trace_id).toBe(frozen["trace_id"]);
    expect(projection.content_identity).toBe(frozen["content_identity"]);
    expect({ ...projection.stats }).toEqual(frozen["stats"]);
    expect([...projection.findings]).toEqual(frozen["findings"]);
    expect({ ...projection.source }).toEqual(frozen["source"]);
  });

  it("writes the disclosure report byte-identically", async () => {
    const projection = await scan();
    const report = serializeDocument(publicationReport(projection, false, null));
    expect(new TextDecoder().decode(report)).toBe(
      new TextDecoder().decode(vector("expected-report.json")),
    );
  });

  it("derives the same attestation from the frozen report", () => {
    const attestation = attestationFromReport(vectorJson("expected-report.json"), {
      reviewer: "Alex Ling",
      license: "CC-BY-4.0",
      consent: CONSENT,
      reviewed_at: REVIEWED_AT,
    });
    expect(new TextDecoder().decode(serializeDocument(attestationDocument(attestation)))).toBe(
      new TextDecoder().decode(vector("expected-attestation.json")),
    );
    expect(attestationFromDict(parseJsonStrict(new TextDecoder().decode(vector("attestation.json"))))).toEqual(
      attestation,
    );
  });

  it("matches the frozen option variants", async () => {
    const frozen = vectorJson("expected-option-digests.json") as Record<
      string,
      Record<string, unknown>
    >;
    const variants: Record<string, Record<string, unknown>> = {
      default: {},
      allow_tool_names: { allow_tool_names: ["reader", "writer"] },
      keep_relative_paths: { keep_relative_paths: true },
      both: { allow_tool_names: ["reader"], keep_relative_paths: true },
    };
    for (const [label, options] of Object.entries(variants)) {
      const projection = await scan(options);
      const expected = frozen[label]!;
      expect(projection.projection_sha256, label).toBe(expected["projection_sha256"]);
      expect(projection.trace_id, label).toBe(expected["trace_id"]);
      expect(projection.content_identity, label).toBe(expected["content_identity"]);
      expect({ ...projection.stats }, label).toEqual(expected["stats"]);
    }
  });
});

describe("publication projection", () => {
  it("drops tool names and makes paths opaque by default", async () => {
    const projection = await scan();
    expect(projection.stats.event_count).toBe(34);
    expect(projection.stats.tool_names_removed).toBe(16);
    expect(projection.stats.tool_names_retained).toBe(0);
    expect(projection.stats.paths_opaque).toBe(1);
    const ledger = new TextDecoder().decode(projection.entries["public/events.ndjson"]!);
    for (const name of ["reader", "writer", "runner", "fetcher", "shelltool"]) {
      expect(ledger).not.toContain(name);
    }
    expect(ledger).not.toContain("$workspace/f.txt");
    expect(ledger).toContain("path-1");
  });

  it("rebinds every ledger record to the fresh trace id", async () => {
    const projection = await scan();
    for (const line of new TextDecoder()
      .decode(projection.entries["public/events.ndjson"]!)
      .split("\n")) {
      if (line.trim() === "") continue;
      const record = parseJsonStrict(line) as Record<string, unknown>;
      expect(record["run_id"]).toBe(projection.trace_id);
    }
    expect(projection.trace_id).not.toBe(projection.source.trace_id);
  });

  it("keeps the manifest profile, provenance, and IR binding", async () => {
    const projection = await scan();
    const manifest = parseJsonStrict(
      new TextDecoder().decode(projection.entries["manifest.json"]!),
    ) as Record<string, unknown>;
    expect(manifest["capture"]).toEqual({
      profile: "publication",
      vault_present: false,
      publication_eligible: true,
      redaction_policy: "publication-v1",
      scanner: { status: "passed", ruleset: "secrets-v1" },
      attested: true,
    });
    expect(manifest["trace_id"]).toBe(projection.trace_id);
    const sourceManifest = parseJsonStrict(
      new TextDecoder().decode(readArchiveEntries(SOURCE_BYTES)["manifest.json"]!),
    ) as Record<string, unknown>;
    expect(manifest["provenance"]).toEqual(sourceManifest["provenance"]);
    expect(manifest["workflow"]).toEqual(sourceManifest["workflow"]);
  });

  it("prepares an archive that verifies as playback-only publication", async () => {
    const { preparePublication } = await import("../publication.js");
    const attestation = attestationFromDict(
      parseJsonStrict(new TextDecoder().decode(vector("attestation.json"))),
    );
    const prepared = await preparePublication(
      SOURCE_PATH,
      SOURCE_BYTES,
      "published.nemotrace",
      attestation,
    );
    const frozen = vectorJson("expected-digests.json");
    expect(prepared.result.content_identity).toBe(frozen["content_identity"]);
    const report = await verifyArchive(prepared.bytes);
    expect(report.errors).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.replayability).toBe("playback-only");
    const entries = readArchiveEntries(prepared.bytes);
    expect(Object.keys(entries).sort()).toEqual([
      "integrity.json",
      "manifest.json",
      "public/events.ndjson",
      "public/summary.json",
      "public/workflow.graph.json",
    ]);
    for (const data of Object.values(entries)) {
      expect(new TextDecoder().decode(data)).not.toContain("sk-parity-TEST-secret-9999");
      expect(new TextDecoder().decode(data)).not.toContain("/work/");
    }
  });
});

describe("publication refusals", () => {
  const replaySource = new Uint8Array(readFileSync(join(VECTORS, "cli", "replay-e2e.nemotrace")));
  const incompleteSource = new Uint8Array(
    readFileSync(join(VECTORS, "cvxpygen-public.nemotrace")),
  );

  it("refuses a replay (vault-bearing) source", async () => {
    await expect(
      scanPublication("replay.nemotrace", replaySource, {}, "replay.nemotrace"),
    ).rejects.toThrow(/requires an 'audit' source/);
  });

  it("refuses incomplete provenance", async () => {
    await expect(
      scanPublication("cvxpygen.nemotrace", incompleteSource, {}, "cvxpygen.nemotrace"),
    ).rejects.toThrow(/complete compiler provenance/);
  });

  it("refuses unknown option values", async () => {
    await expect(scan({ allow_tool_names: ["not/a name"] })).rejects.toThrow(
      /not a safe static declaration/,
    );
  });

  it("refuses a tampered source and never claims a pass", async () => {
    const entries = readArchiveEntries(SOURCE_BYTES);
    entries["manifest.json"] = new TextEncoder().encode(
      new TextDecoder().decode(entries["manifest.json"]!).replace("LoopTest", "LoopTest2"),
    );
    const tampered = writeArchive(entries);
    await expect(scanPublication("x.nemotrace", tampered, {}, "x.nemotrace")).rejects.toThrow(
      /does not verify/,
    );
  });

  it("refuses to attest a failed scan", () => {
    const report = vectorJson("expected-report.json");
    report["scan"] = { ruleset: "secrets-v1", status: "failed", findings: ["x"], findings_count: 1 };
    expect(() =>
      attestationFromReport(report, {
        reviewer: "Alex Ling",
        license: "CC-BY-4.0",
        consent: CONSENT,
      }),
    ).toThrow(/did not pass/);
  });

  it("refuses an attestation that does not cover the projection", async () => {
    const { preparePublication } = await import("../publication.js");
    const attestation = attestationFromDict(
      parseJsonStrict(new TextDecoder().decode(vector("attestation.json"))),
    );
    const forged = { ...attestation, projection_sha256: `sha256:${"11".repeat(32)}` };
    await expect(
      preparePublication(SOURCE_PATH, SOURCE_BYTES, "out.nemotrace", forged),
    ).rejects.toThrow(/does not cover this projection/);
  });

  it("refuses a source identity mismatch", async () => {
    const { preparePublication } = await import("../publication.js");
    const attestation = attestationFromDict(
      parseJsonStrict(new TextDecoder().decode(vector("attestation.json"))),
    );
    const forged = { ...attestation, source_content_identity: `sha256:${"22".repeat(32)}` };
    await expect(
      preparePublication(SOURCE_PATH, SOURCE_BYTES, "out.nemotrace", forged),
    ).rejects.toThrow(/content identity/);
  });

  it("reports scanner findings instead of publishing", async () => {
    const poisoned = await rebuildSource((events) => {
      events["0"] = {
        ...events["0"]!,
        metadata: { ...(events["0"]!["metadata"] as Record<string, unknown>), workflow_id: "/home/alice/private-run" },
      };
    });
    const projection = await scanPublication("poisoned.nemotrace", poisoned, {}, "poisoned.nemotrace");
    expect(projection.findings.length).toBeGreaterThan(0);
    expect(projection.findings.join(" ")).toContain("home_path");
    const { preparePublication } = await import("../publication.js");
    const attestation = attestationFromDict(
      parseJsonStrict(new TextDecoder().decode(vector("attestation.json"))),
    );
    await expect(
      preparePublication("poisoned.nemotrace", poisoned, "out.nemotrace", attestation),
    ).rejects.toThrow(/does not cover this projection|scanner blocked export/);
  });
});

// A forward-compatible reader tolerates unknown fields; the publication
// transform must not. These tests poison a structurally valid audit archive
// with ordinary (non-secret-pattern) private text and prove the transform
// refuses or drops it instead of republishing it.
describe("publication-v1 nested allowlists (H-S1)", () => {
  async function poisonedSource(
    mutate: (events: Record<string, Record<string, unknown>>) => void,
  ): Promise<Uint8Array> {
    return rebuildSource(mutate);
  }

  it("refuses an unknown metadata field", async () => {
    const poisoned = await poisonedSource((events) => {
      const first = events["0"]!;
      first["metadata"] = {
        ...(first["metadata"] as Record<string, unknown>),
        private_note: "patient narrative: seasonal allergies",
      };
    });
    await expect(
      scanPublication("poisoned.nemotrace", poisoned, {}, "poisoned.nemotrace"),
    ).rejects.toThrow(/refusing to republish unknown structure/);
  });

  it("refuses an out-of-shape metadata value", async () => {
    const poisoned = await poisonedSource((events) => {
      const first = events["0"]!;
      first["metadata"] = { ...(first["metadata"] as Record<string, unknown>), duration_ms: "fast" };
    });
    await expect(
      scanPublication("poisoned.nemotrace", poisoned, {}, "poisoned.nemotrace"),
    ).rejects.toThrow(/metadata field 'duration_ms' does not match the publication-v1 shape/);
  });

  it("refuses free text in an output scalar", async () => {
    const poisoned = await poisonedSource((events) => {
      for (const record of Object.values(events)) {
        if (record["output"] !== undefined && record["output"] !== null) {
          (record["output"] as Record<string, unknown>)["note"] =
            "patient narrative: seasonal allergies";
        }
      }
    });
    await expect(
      scanPublication("poisoned.nemotrace", poisoned, {}, "poisoned.nemotrace"),
    ).rejects.toThrow(/output field 'note' does not match the publication-v1 shape/);
  });

  it("refuses an absolute args path even when paths are kept", async () => {
    const poisoned = await poisonedSource((events) => {
      for (const record of Object.values(events)) {
        if (record["args"] !== undefined && record["args"] !== null) {
          (record["args"] as Record<string, unknown>)["path"] =
            "/home/alice/private/candidate.py";
        }
      }
    });
    await expect(
      scanPublication(
        "poisoned.nemotrace",
        poisoned,
        { keep_relative_paths: true },
        "poisoned.nemotrace",
      ),
    ).rejects.toThrow(/args field 'path' does not match the publication-v1 shape/);
  });

  it("drops an unrecognized args name but keeps a redaction pointer", async () => {
    const poisoned = await poisonedSource((events) => {
      for (const record of Object.values(events)) {
        if (record["args"] !== undefined && record["args"] !== null) {
          (record["args"] as Record<string, unknown>)["private_hint"] =
            "seasonal allergies";
        }
      }
    });
    const projection = await scanPublication(
      "poisoned.nemotrace",
      poisoned,
      {},
      "poisoned.nemotrace",
    );
    const text = new TextDecoder().decode(projection.entries["public/events.ndjson"]!);
    expect(text).not.toContain("seasonal allergies");
    const records = text
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => parseJsonStrict(line) as Record<string, unknown>);
    const started = records.find(
      (record) =>
        record["kind"] === "tool_call_started" &&
        (record["redacted_fields"] as string[]).includes("/args/private_hint"),
    );
    expect(started).toBeDefined();
    expect(Object.keys(started!["args"] as Record<string, unknown>)).not.toContain(
      "private_hint",
    );
  });

  it("refuses annotation fields on a plain record", async () => {
    const poisoned = await poisonedSource((events) => {
      events["0"] = { ...events["0"]!, anchor_sequence: 1 };
    });
    await expect(
      scanPublication("poisoned.nemotrace", poisoned, {}, "poisoned.nemotrace"),
    ).rejects.toThrow(/carries annotation fields/);
  });
});
