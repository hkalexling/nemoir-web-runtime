/**
 * Regression tests for NEMOTRACE_PHASE_1_REVIEW follow-up 2026-09-08.
 * Mirrors python test_review_followup.py: verifier depth, forward-compat,
 * unsafe-int, observer isolation, lone-surrogate, responseBytes parity.
 */
import { describe, expect, it } from "vitest";
import { WorkflowEventEmitter } from "../events.js";
import { responseBytes } from "../trace.js";
import { canonicalStringify } from "../canonical.js";
import { WorkflowRuntime } from "../runtime.js";
import { ToolRegistry } from "../tools.js";
import { TraceRecorder, verifyArchive } from "../trace.js";
import { makeManifest, makeStage, makeWrite, makeInput, guard, makeTransition } from "./helpers.js";
import { unzipSync, zipSync } from "fflate";

const FIXED_TRACE_ID = "0123456789abcdef0123456789abcdef";
const FIXED_TIME = new Date("2026-01-02T03:04:05.000Z");

function fixedClock() { return new Date(FIXED_TIME); }

function traceManifest() {
  const stages = [
    makeStage("Start", {
      writes: [makeWrite("note", "string")],
      transitions: [makeTransition("Done", 0, "explicit_transition", guard.always())],
    }),
    makeStage("Done", { writes: [makeWrite("summary", "string")] }),
  ];
  return makeManifest(stages, {
    workflowId: "FollowUp",
    entryId: "Start",
    exitIds: new Set(["Done"]),
    inputs: [makeInput("p", "string")],
  });
}

async function buildValidArchive(): Promise<Uint8Array> {
  const manifest = traceManifest() as any;
  const rec = new TraceRecorder({
    path: "run.nemotrace",
    profile: "audit",
    provenance: { frontend: "nemo_dsl", target: "web", compilerVersion: "0.1.9", irVersion: "0.1", irSha256: "sha256:"+"ab".repeat(32) },
    traceId: FIXED_TRACE_ID,
    clock: fixedClock,
  } as any);
  // Use scripted executor to drive runtime and fill ledger
  const runtime = new WorkflowRuntime({
    manifest,
    tools: new ToolRegistry([]),
    stageExecutor: {
      async execute(ctx) {
        if (ctx.stage.id === "Start") return { note: "hello" };
        return { summary: "bye" };
      },
    },
  });
  await runtime.run({ p: "x" } as any, { traceRecorder: rec as any });
  const bytes = rec.archiveBytes;
  if (!bytes) throw new Error("archiveBytes missing after run");
  return bytes;
}

function readEntries(bytes: Uint8Array): Record<string, Uint8Array> {
  return unzipSync(bytes) as Record<string, Uint8Array>;
}

async function writeEntries(entries: Record<string, Uint8Array>): Promise<Uint8Array> {
  // Recompute integrity/content identity like python helper
  const payloads: Record<string, Uint8Array> = { ...entries };
  delete (payloads as any)["integrity.json"];
  const enc = new TextEncoder();
  // need sha helper - use subtle? For test we can use node crypto via verify helper? Simpler: use TraceRecorder internal?
  // Instead, we can reuse verifyArchive's recompute isn't needed; we can manually compute sha via crypto.subtle synchronously using helper from trace.ts? For test we import sha helper via dynamic.
  // Use simple helper: compute via Node's crypto if available
  const cryptoMod = await import("node:crypto");
  function shaTag(data: Uint8Array): string {
    return "sha256:" + cryptoMod.createHash("sha256").update(data).digest("hex");
  }
  const integrityEntries: any[] = [];
  for (const name of Object.keys(payloads).sort()) {
    const data = payloads[name];
    integrityEntries.push({
      path: name,
      media_type: name.endsWith(".ndjson") ? "application/x-ndjson" : "application/json",
      uncompressed_bytes: data.length,
      sha256: shaTag(data),
    });
  }
  const identityEntries = [...integrityEntries].sort((a,b)=> a.path < b.path ? -1 : a.path > b.path ? 1 : 0).map(e=> ({path:e.path, sha256:e.sha256, uncompressed_bytes:e.uncompressed_bytes}));
  const identityObj = { format: "nemoir.trace.content-identity/0.1", entries: identityEntries };
  const identityBytes = enc.encode(canonicalStringify(identityObj));
  const contentId = shaTag(identityBytes);
  const integrityObj = { format: "nemoir.trace.integrity/0.1", algorithm: "sha256", entries: integrityEntries, content_identity: contentId };
  (payloads as any)["integrity.json"] = enc.encode(canonicalStringify(integrityObj));
  const sortedPayloads: Record<string, Uint8Array> = {};
  for (const name of Object.keys(payloads).sort()) sortedPayloads[name] = payloads[name];
  return zipSync(sortedPayloads, { level: 6, mtime: new Date("1980-01-01T00:00:00Z") });
}

describe("review follow-up", () => {
  it("verifier rejects numeric stage_id", async () => {
    const valid = await buildValidArchive();
    const entries = readEntries(valid);
    const dec = new TextDecoder();
    const enc = new TextEncoder();
    const lines = dec.decode(entries["public/events.ndjson"]).split("\n").filter(l=>l.trim());
    const objs = lines.map(l=> JSON.parse(l));
    for (const o of objs) if (o.kind==="stage_started") { o.stage_id = 7; break; }
    entries["public/events.ndjson"] = enc.encode(objs.map(o=> canonicalStringify(o)).join("\n")+"\n");
    const bad = await writeEntries(entries);
    const report = await verifyArchive(bad);
    expect(report.ok).toBe(false);
    expect(report.errors.some(e=> e.includes("stage_id"))).toBe(true);
  });

  it("verifier handles incomplete integrity without crash", async () => {
    const valid = await buildValidArchive();
    const entries = readEntries(valid);
    const dec = new TextDecoder();
    const enc = new TextEncoder();
    const integrity = JSON.parse(dec.decode(entries["integrity.json"]));
    if (integrity.entries.length) integrity.entries[0] = { path: integrity.entries[0].path };
    entries["integrity.json"] = enc.encode(canonicalStringify(integrity));
    // Need to keep hashes consistent for other entries but integrity entry itself is now inconsistent; we rebuild via manual zip without recompute helper
    // Write raw zip with bad integrity (don't recompute via helper)
    const rawPayloads: Record<string, Uint8Array> = { ...entries };
    const bad = zipSync(rawPayloads, { level: 6, mtime: new Date("1980-01-01T00:00:00Z") });
    const report = await verifyArchive(bad);
    expect(report.ok).toBe(false);
    expect(report.errors.some(e=> e.toLowerCase().includes("integrity"))).toBe(true);
  });

  it("observer does not prevent sink on failure", async () => {
    const received: string[] = [];
    const sink = async (ev:any)=> { received.push(ev.kind); };
    const failingObserver = async (_:any)=> { throw new Error("boom"); };
    const emitter = new WorkflowEventEmitter("abc", sink as any, failingObserver as any);
    await emitter.emit("run_started", { metadata: { workflowId: "x", entry: "Start" } } as any);
    expect(received).toContain("run_started");
  });

  it("lone surrogate validation consistent (runtime rejects)", async () => {
    const manifest = traceManifest() as any;
    const lone = "\uD800";
    const runtime = new WorkflowRuntime({
      manifest,
      tools: new ToolRegistry([]),
      stageExecutor: {
        async execute(ctx) {
          if (ctx.stage.id==="Start") return { note: lone };
          return { summary: "bye" };
        },
      },
    });
    await expect(runtime.run({ p: "x" } as any)).rejects.toThrow();
    const rec = new TraceRecorder({
      path: "run.nemotrace",
      profile: "audit",
      provenance: { frontend: "nemo_dsl", target: "web", compilerVersion: "0.1.9", irVersion: "0.1", irSha256: "sha256:"+"ab".repeat(32) },
      traceId: FIXED_TRACE_ID,
      clock: fixedClock,
    } as any);
    await expect(runtime.run({ p: "x" } as any, { traceRecorder: rec as any })).rejects.toThrow();
  });

  it("responseBytes canonical parity for unicode", () => {
    const bytes = responseBytes({ content: null, toolCalls: [{ arguments: { a: 1, label: "é" } }] } as any);
    const expected = new TextEncoder().encode(canonicalStringify({ a: 1, label: "é" })).length;
    expect(bytes).toBe(expected);
    expect(bytes).toBe(20);
    expect(bytes).not.toBe(27);
    const nested = responseBytes({ content: null, toolCalls: [{ arguments: { a: 1, nested: { x: [1,2] } } }] } as any);
    expect(nested).toBe(new TextEncoder().encode(canonicalStringify({ a: 1, nested: { x: [1,2] } })).length);
  });

  it("forward-compat extra field is warning not error", async () => {
    const valid = await buildValidArchive();
    const entries = readEntries(valid);
    const dec = new TextDecoder(); const enc = new TextEncoder();
    const objs = dec.decode(entries["public/events.ndjson"]).split("\n").filter(l=>l.trim()).map(l=> JSON.parse(l));
    for (const o of objs) if (o.kind==="run_started") { o.future_writer_field = "hello"; break; }
    const manifest = JSON.parse(dec.decode(entries["manifest.json"]));
    manifest.future_manifest_field = "world";
    entries["manifest.json"] = enc.encode(canonicalStringify(manifest));
    entries["public/events.ndjson"] = enc.encode(objs.map(o=> canonicalStringify(o)).join("\n")+"\n");
    const good = await writeEntries(entries);
    const report = await verifyArchive(good);
    expect(report.ok).toBe(true);
    expect(report.warnings.some(w=> w.includes("unexpected fields"))).toBe(true);
  });

  it("unsafe int in summary rejected", async () => {
    const valid = await buildValidArchive();
    const entries = readEntries(valid);
    const dec = new TextDecoder(); const enc = new TextEncoder();
    const summary = JSON.parse(dec.decode(entries["public/summary.json"]));
    summary.duration_ms = 9007199254740993;
    entries["public/summary.json"] = enc.encode(canonicalStringify(summary));
    const bad = await writeEntries(entries);
    const report = await verifyArchive(bad);
    expect(report.ok).toBe(false);
    expect(report.errors.some(e=> e.includes("unsafe"))).toBe(true);
  });

  it("unsafe int in events rejected", async () => {
    const valid = await buildValidArchive();
    const entries = readEntries(valid);
    const dec = new TextDecoder(); const enc = new TextEncoder();
    const objs = dec.decode(entries["public/events.ndjson"]).split("\n").filter(l=>l.trim()).map(l=> JSON.parse(l));
    objs[0].metadata = objs[0].metadata || {};
    objs[0].metadata.response_bytes = 9007199254740993;
    entries["public/events.ndjson"] = enc.encode(objs.map(o=> canonicalStringify(o)).join("\n")+"\n");
    const bad = await writeEntries(entries);
    const report = await verifyArchive(bad);
    expect(report.ok).toBe(false);
    expect(report.errors.some(e=> e.includes("unsafe"))).toBe(true);
  });
});
