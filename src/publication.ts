/**
 * NemoTrace publication transform (Phase 5) — TypeScript mirror.
 *
 * Turns one `audit` trace into one stricter, vault-free `publication` artifact
 * (`plan.md` §5.4, `docs/trace/redaction-policy.md` §1). Publication is a fresh
 * projection, never a bit flipped on an existing archive:
 *
 * 1. the source must verify, be an `audit` profile with no vault, carry
 *    complete compiler provenance, and be `complete` or `failed`;
 * 2. the public ledger is re-projected under `publication-v1` — tool names are
 *    dropped unless explicitly reviewed, and alias-relative paths become opaque
 *    `path-N` refs;
 * 3. the artifact gets a fresh trace id derived from the projection digest, so
 *    it does not correlate with the local private run;
 * 4. a human reviews a disclosure report (`scanPublication`) and signs an
 *    attestation covering the reviewed projection digest; only then may
 *    `preparePublication` write the archive;
 * 5. the `secrets-v1` scanner runs as a blocking gate over every cleartext
 *    entry and filename, and the output never contains a vault.
 *
 * This mirrors `python/nemoir-runtime/src/nemoir_runtime/publication.py`; both
 * must produce byte-identical archives for the same source and options.
 */

import {
  canonicalStringify,
  parseJsonStrict,
  sha256Tag,
  toCanonicalBytes,
} from "./canonical.js";
import {
  CONTENT_IDENTITY_FORMAT,
  EVENTS_PATH,
  GRAPH_PATH,
  INTEGRITY_PATH,
  MANIFEST_PATH,
  SCANNER_RULESET,
  SUMMARY_FORMAT,
  SUMMARY_PATH,
  TRACE_FORMAT,
  TraceError,
  readArchiveEntries,
  scanCleartextEntries,
  verifyArchive,
  writeArchive,
} from "./trace.js";
import type { VerificationReport } from "./trace.js";

export const PUBLICATION_PROJECTION_FORMAT = "nemoir.trace.publication-projection/0.1";
export const PUBLICATION_ATTESTATION_FORMAT = "nemoir.trace.publication-attestation/0.1";
export const PUBLICATION_REPORT_FORMAT = "nemoir.trace.publication-report/0.1";
export const PUBLICATION_REDACTION_POLICY = "publication-v1";
const PUBLICATION_ID_DOMAIN = "nemoir.trace.publication-id/0.1\u0000";

/** Source gates: audit only, no vault, no interrupted runs. */
export const SOURCE_PROFILE = "audit";
export const PUBLISHABLE_STATUSES = ["complete", "failed"] as const;

const GRAPH_FORMAT = "nemoir.trace.workflow-graph/0.1";

const LEDGER_KINDS = new Set([
  "run_started",
  "stage_started",
  "model_delta",
  "model_completed",
  "model_retry",
  "tool_call_started",
  "tool_call_completed",
  "tool_call_failed",
  "policy_checked",
  "policy_denied",
  "transition_selected",
  "stage_completed",
  "run_completed",
  "run_failed",
  "annotation",
]);

const MANIFEST_KEYS = new Set([
  "format",
  "trace_id",
  "created_at",
  "status",
  "capture",
  "workflow",
  "provenance",
  "integrity",
  "viewer",
]);
const CAPTURE_KEYS = new Set([
  "profile",
  "vault_present",
  "publication_eligible",
  "redaction_policy",
  "scanner",
  "attested",
]);
const WORKFLOW_KEYS = new Set(["id", "ir_version", "ir_sha256", "entry", "exits"]);
const PROVENANCE_KEYS = new Set([
  "complete",
  "frontend",
  "target",
  "compiler_version",
  "runtime",
  "model",
]);
const REQUIRED_PROVENANCE_KEYS = ["complete", "frontend", "target", "compiler_version", "runtime"];
const RUNTIME_KEYS = new Set(["name", "version"]);
const MODEL_KEYS = new Set(["name", "api_mode", "sampling"]);
const SAMPLING_KEYS = new Set(["temperature", "max_tokens"]);
const VIEWER_KEYS = new Set(["min_format"]);
const GRAPH_KEYS = new Set(["format", "workflow_id", "entry", "exits", "nodes", "transitions", "policies"]);
const NODE_KEYS = new Set(["id", "execution", "capabilities", "writes"]);
const WRITE_KEYS = new Set(["name", "type", "optional"]);
const TRANSITION_KEYS = new Set(["from", "to", "priority", "guard_kind"]);
const POLICY_KEYS = new Set(["ref", "kind", "trigger_capability", "required_capabilities"]);
const ATTESTATION_KEYS = new Set([
  "format",
  "source",
  "projection",
  "options",
  "reviewer",
  "reviewed_at",
  "license",
  "consent",
]);
const ATTESTATION_SOURCE_KEYS = new Set(["content_identity", "trace_id"]);
const ATTESTATION_PROJECTION_KEYS = new Set(["sha256"]);
const OPTIONS_KEYS = new Set(["allow_tool_names", "keep_relative_paths"]);

// Strict publication-v1 allowlists. A forward-compatible *reader* tolerates
// unknown fields (schema README §1); the publication transform must not,
// because a published artifact asserts what it contains. Sets mirror
// `docs/trace/schema/public-event.schema.json` exactly.
const PUBLIC_EVENT_KEYS = new Set([
  "kind",
  "run_id",
  "sequence",
  "timestamp",
  "stage_id",
  "stage_visit_id",
  "model_call_id",
  "tool_call_id",
  "channel",
  "text",
  "capability",
  "tool_name",
  "args",
  "output",
  "result",
  "error",
  "transition_to",
  "metadata",
  "redacted_fields",
  "anchor_sequence",
  "annotation",
]);
const METADATA_KEYS = new Set([
  "approval",
  "attempt",
  "byte_count",
  "category",
  "code_bytes",
  "command_id",
  "content_omitted",
  "cost_usd",
  "denied",
  "duration_ms",
  "entry",
  "error_code",
  "error_type",
  "exit_class",
  "input_bytes",
  "input_tokens",
  "max_retries",
  "method",
  "origin_class",
  "output_tokens",
  "path_ref",
  "policy_kind",
  "policy_ref",
  "priority",
  "reason",
  "required_capabilities",
  "response_bytes",
  "result_status",
  "result_type",
  "root_class",
  "status_class",
  "step_count",
  "total_tokens",
  "value_type",
  "workflow_id",
]);
// `args` names are open tool-domain data: the audit writer mirrors arbitrary
// argument names as markers for `user.*` / `browser.*` capabilities, so an
// unrecognized name is dropped with a redaction pointer instead of refusing
// an otherwise-valid source.
const PUBLIC_ARGS_KEYS = new Set([
  "path",
  "path_ref",
  "root_class",
  "content",
  "command_id",
  "method",
  "origin_class",
  "key",
  "value",
  "code",
  "input",
  "headers",
  "body",
  "question",
  "message",
  "options",
]);
const ARGS_MARKER_KEYS = new Set([
  "content",
  "key",
  "value",
  "code",
  "input",
  "headers",
  "body",
  "question",
  "message",
  "options",
]);
const NON_ANNOTATION_KEYS = new Set(["annotation", "anchor_sequence"]);
const METADATA_BOOLS = new Set(["approval", "content_omitted", "denied"]);
const METADATA_ENUMS = new Map<string, ReadonlySet<string>>([
  ["exit_class", new Set(["success", "failure", "signal", "timeout"])],
  ["policy_kind", new Set(["before", "deny"])],
  ["value_type", new Set(["string", "number", "boolean", "object", "array", "null", "binary"])],
  [
    "reason",
    new Set([
      "explicit_transition",
      "backward_ref_loop",
      "next_stage_required_input_available",
      "skip_next_stage_required_input_missing",
      "fallthrough",
      "other",
    ]),
  ],
]);
const METADATA_INT_MINIMUMS = new Map<string, number>([
  ["attempt", 1],
  ["byte_count", 0],
  ["code_bytes", 0],
  ["duration_ms", 0],
  ["input_bytes", 0],
  ["input_tokens", 0],
  ["max_retries", 0],
  ["output_tokens", 0],
  ["priority", 0],
  ["response_bytes", 0],
  ["step_count", 0],
  ["total_tokens", 0],
]);
const METADATA_PATTERNS = new Map<string, RegExp>([
  ["category", /^[a-z][a-z0-9_]*$/],
  ["command_id", /^[A-Za-z0-9][A-Za-z0-9._:-]*$/],
  ["error_code", /^[a-z][a-z0-9_]*$/],
  ["error_type", /^[A-Za-z][A-Za-z0-9_]*$/],
  ["method", /^[A-Z]+$/],
  ["origin_class", /^[A-Za-z0-9][A-Za-z0-9._:-]*$/],
  ["path_ref", /^path-[1-9][0-9]*$/],
  ["policy_ref", /^p-[1-9][0-9]*$/],
  ["result_status", /^[a-z][a-z0-9_]*$/],
  ["result_type", /^[a-z][a-z0-9_]*$/],
  ["root_class", /^\$[a-z][a-z0-9_]*$/],
  ["status_class", /^[1-5]xx$/],
]);
const METADATA_MAX_LENGTHS = new Map<string, number>([
  ["category", 64],
  ["command_id", 128],
  ["entry", 256],
  ["error_code", 64],
  ["error_type", 128],
  ["method", 16],
  ["origin_class", 128],
  ["result_status", 64],
  ["result_type", 64],
  ["workflow_id", 256],
]);
// Bounds for the few `public_args` values that are plain strings rather than
// opaque markers.
const MAX_ARGS_PATH_LEN = 512;
const MAX_ARGS_METHOD_LEN = 16;
const MAX_ARGS_CLASS_LEN = 128;
const MAX_CAPABILITY_NAME_LEN = 128;

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const TOOL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const TRACE_ID_RE = /^[0-9a-f]{32}$/;
const MAX_TOOL_NAME_LEN = 128;
const MAX_REVIEWER_LEN = 200;
const MAX_LICENSE_LEN = 64;
const MAX_CONSENT_LEN = 500;

export class PublicationError extends TraceError {
  constructor(message: string) {
    super(message);
    this.name = "PublicationError";
  }
}

// ---------------------------------------------------------------------------
// Options, attestation, and result types
// ---------------------------------------------------------------------------

export interface PublicationOptions {
  /**
   * Retains reviewed static host tool declarations; everything else is dropped
   * from the public ledger.
   */
  readonly allow_tool_names?: readonly string[];
  /**
   * Keeps alias-relative `$alias/...` arguments instead of opaque `path-N`
   * refs, and therefore requires explicit human review.
   */
  readonly keep_relative_paths?: boolean;
}

/** Canonical options object (part of the reviewed digest and sidecars). */
export interface PublicationOptionsDict {
  readonly allow_tool_names: readonly string[];
  readonly keep_relative_paths: boolean;
}

type NormalizedOptions = PublicationOptionsDict;

function normalizeOptions(options: PublicationOptions | undefined): NormalizedOptions {
  const names = [...new Set((options?.allow_tool_names ?? []).filter((name) => name !== ""))].sort();
  for (const name of names) {
    if (name.length > MAX_TOOL_NAME_LEN || !TOOL_NAME_RE.test(name)) {
      throw new PublicationError(`allowed tool name '${name}' is not a safe static declaration`);
    }
  }
  return { allow_tool_names: names, keep_relative_paths: options?.keep_relative_paths === true };
}

function optionsAsDict(options: NormalizedOptions): PublicationOptionsDict {
  return {
    allow_tool_names: [...options.allow_tool_names],
    keep_relative_paths: options.keep_relative_paths,
  };
}

export interface PublicationSource {
  readonly archive: string;
  readonly trace_id: string;
  readonly content_identity: string;
  readonly profile: string;
  readonly status: string;
  readonly created_at: string;
}

export interface PublicationStats {
  readonly event_count: number;
  readonly stage_visit_count: number;
  readonly tool_names_removed: number;
  readonly tool_names_retained: number;
  readonly paths_opaque: number;
  readonly redaction_markers: number;
  readonly annotations: number;
}

export interface PublicationAttestation {
  readonly reviewer: string;
  readonly reviewed_at: string;
  readonly license: string;
  readonly consent: string;
  readonly source_content_identity: string;
  readonly source_trace_id: string;
  readonly projection_sha256: string;
  readonly options: PublicationOptionsDict;
}

export interface PublicationProjection {
  readonly entries: Record<string, Uint8Array>;
  readonly trace_id: string;
  readonly projection_sha256: string;
  readonly content_identity: string;
  readonly source: PublicationSource;
  readonly stats: PublicationStats;
  readonly findings: readonly string[];
  readonly scanned_entries: readonly string[];
  readonly options: NormalizedOptions;
}

export interface PublicationResult {
  readonly destination: string;
  readonly trace_id: string;
  readonly projection_sha256: string;
  readonly content_identity: string;
  readonly compressed_bytes: number;
  readonly source: PublicationSource;
  readonly stats: PublicationStats;
}

// ---------------------------------------------------------------------------
// Structural helpers
// ---------------------------------------------------------------------------

/**
 * Render a scalar/list the way Python's `repr`/`str` does in the mirrored
 * messages, so cross-runtime stderr stays byte-identical.
 */
function reprLike(value: unknown): string {
  if (typeof value === "string") return `'${value}'`;
  if (value === null || value === undefined) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (Array.isArray(value)) return `[${value.map(reprLike).join(", ")}]`;
  return String(value);
}

function asDict(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new PublicationError(`publication ${what} must be an object`);
  }
  return value as Record<string, unknown>;
}

function asList(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new PublicationError(`publication ${what} must be an array`);
  return value as unknown[];
}

function asString(value: unknown, what: string): string {
  if (typeof value !== "string" || value === "") {
    throw new PublicationError(`publication ${what} must be a non-empty string`);
  }
  return value;
}

function asStringList(value: unknown, what: string): string[] {
  return asList(value, what).map((item) => asString(item, `${what} item`));
}

function requireKeys(
  node: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  what: string,
  required: readonly string[] = [],
): void {
  const missing = required.filter((key) => !(key in node));
  if (missing.length > 0) {
    throw new PublicationError(`publication ${what} is missing ${reprLike([...missing].sort())}`);
  }
  const unknown = Object.keys(node)
    .filter((key) => !allowed.has(key))
    .sort();
  if (unknown.length > 0) {
    throw new PublicationError(
      `publication ${what} has fields this transform does not understand: ` +
        `${reprLike(unknown)}; refusing to republish unknown structure`,
    );
  }
}

/** True for a `common.schema.json` redaction marker (opaque by design). */
function isMarker(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const marker = value as Record<string, unknown>;
  return marker["$redacted"] !== null && typeof marker["$redacted"] === "object";
}

/** The closed `public_scalar` set: null, boolean, finite number, or marker. */
function publicScalarOk(value: unknown): boolean {
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "number") {
    return Number.isFinite(value) && (!Number.isInteger(value) || Math.abs(value) <= Number.MAX_SAFE_INTEGER);
  }
  return isMarker(value);
}

/** Per-key shape check mirroring `public-event.schema.json` metadata. */
function metadataValueOk(key: string, value: unknown): boolean {
  if (METADATA_BOOLS.has(key)) return typeof value === "boolean";
  const enums = METADATA_ENUMS.get(key);
  if (enums !== undefined) return typeof value === "string" && enums.has(value);
  const minimum = METADATA_INT_MINIMUMS.get(key);
  if (minimum !== undefined) {
    return typeof value === "number" && Number.isInteger(value) && value >= minimum;
  }
  if (key === "cost_usd") {
    return typeof value === "number" && Number.isFinite(value) && value >= 0;
  }
  if (key === "required_capabilities") {
    return (
      Array.isArray(value) &&
      (value as unknown[]).every(
        (item) => typeof item === "string" && item.length >= 1 && item.length <= MAX_CAPABILITY_NAME_LEN,
      )
    );
  }
  const pattern = METADATA_PATTERNS.get(key);
  if (pattern !== undefined) {
    const limit = METADATA_MAX_LENGTHS.get(key);
    return (
      typeof value === "string" &&
      pattern.test(value) &&
      (limit === undefined || value.length <= limit)
    );
  }
  const limit = METADATA_MAX_LENGTHS.get(key);
  if (limit !== undefined) {
    return typeof value === "string" && value.length >= 1 && value.length <= limit;
  }
  return false; // unreachable for allowlisted keys; fail closed if a set drifts.
}

/** Per-key shape check mirroring `public-event.schema.json` public_args. */
function argValueOk(key: string, value: unknown): boolean {
  if (ARGS_MARKER_KEYS.has(key)) return isMarker(value);
  if (key === "path") {
    return typeof value === "string" && value.startsWith("$") && value.length <= MAX_ARGS_PATH_LEN;
  }
  if (key === "root_class") {
    return typeof value === "string" && /^\$[a-z][a-z0-9_]*$/.test(value);
  }
  if (key === "path_ref") {
    return typeof value === "string" && /^path-[1-9][0-9]*$/.test(value);
  }
  if (key === "method") {
    return typeof value === "string" && /^[A-Z]+$/.test(value) && value.length <= MAX_ARGS_METHOD_LEN;
  }
  if (key === "command_id" || key === "origin_class") {
    return (
      typeof value === "string" &&
      /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value) &&
      value.length <= MAX_ARGS_CLASS_LEN
    );
  }
  return false; // unreachable for allowlisted keys; fail closed if a set drifts.
}

/**
 * Enforce the `publication-v1` nested allowlists on one ledger record.
 *
 * The reader tolerates forward-compatible fields; publication refuses them:
 * a field this transform does not classify must never reach a published
 * artifact. `args` names are the one exception (open tool-domain names are
 * dropped with a redaction pointer), and annotation payloads are already
 * shape-gated by `verifyArchive`.
 */
function validateRecordShape(record: Record<string, unknown>, redacted: string[]): void {
  requireKeys(record, PUBLIC_EVENT_KEYS, "source ledger record", [
    "kind",
    "run_id",
    "timestamp",
    "redacted_fields",
  ]);
  if (record["kind"] !== "annotation") {
    const present = [...NON_ANNOTATION_KEYS].filter((key) => key in record).sort();
    if (present.length > 0) {
      throw new PublicationError(
        `publication source ledger record of kind ${reprLike(record["kind"])} ` +
          `carries annotation fields ${reprLike(present)}`,
      );
    }
  }
  const metadata = record["metadata"];
  if (metadata !== undefined && metadata !== null) {
    const metadataMap = asDict(metadata, "source ledger metadata");
    requireKeys(metadataMap, METADATA_KEYS, "source ledger metadata");
    for (const key of Object.keys(metadataMap).sort()) {
      if (!metadataValueOk(key, metadataMap[key])) {
        throw new PublicationError(
          `publication source ledger metadata field ${reprLike(key)} ` +
            "does not match the publication-v1 shape",
        );
      }
    }
  }
  const output = record["output"];
  if (output !== undefined && output !== null) {
    const outputMap = asDict(output, "source ledger output");
    for (const key of Object.keys(outputMap).sort()) {
      if (!publicScalarOk(outputMap[key])) {
        throw new PublicationError(
          `publication source ledger output field ${reprLike(key)} ` +
            "does not match the publication-v1 shape",
        );
      }
    }
  }
  const args = record["args"];
  if (args !== undefined && args !== null) {
    const argsMap = asDict(args, "source ledger args");
    for (const key of Object.keys(argsMap).sort()) {
      if (!PUBLIC_ARGS_KEYS.has(key)) {
        redacted.push(`/args/${key}`);
        continue;
      }
      if (!argValueOk(key, argsMap[key])) {
        throw new PublicationError(
          `publication source ledger args field ${reprLike(key)} ` +
            "does not match the publication-v1 shape",
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Source validation
// ---------------------------------------------------------------------------

interface SourceFacts {
  readonly manifest: Record<string, unknown>;
  readonly source: PublicationSource;
}

function validateManifest(entries: Record<string, Uint8Array>): SourceFacts {
  const manifest = asDict(
    parseJsonStrict(new TextDecoder().decode(entries[MANIFEST_PATH])),
    "source manifest",
  );
  requireKeys(manifest, MANIFEST_KEYS, "source manifest", [...MANIFEST_KEYS]);
  const capture = asDict(manifest["capture"], "source manifest capture");
  requireKeys(capture, CAPTURE_KEYS, "source manifest capture", ["profile", "vault_present"]);
  const profile = capture["profile"];
  if (profile !== SOURCE_PROFILE) {
    throw new PublicationError(
      `publication requires an '${SOURCE_PROFILE}' source archive, got ${reprLike(profile)}: ` +
        "vault-bearing and already-published archives are refused",
    );
  }
  if (capture["vault_present"] !== false) {
    throw new PublicationError("publication refuses a source archive that declares a vault");
  }
  if ("private/vault.enc" in entries || "private/vault.meta.json" in entries) {
    throw new PublicationError("publication refuses a source archive that carries vault entries");
  }
  const status = manifest["status"];
  if (status !== "complete" && status !== "failed") {
    throw new PublicationError(
      `publication requires a complete or failed source run, got ${reprLike(status)} ` +
        "(interrupted runs carry partial evidence)",
    );
  }
  const workflow = asDict(manifest["workflow"], "source manifest workflow");
  requireKeys(workflow, WORKFLOW_KEYS, "source manifest workflow", [...WORKFLOW_KEYS]);
  const provenance = asDict(manifest["provenance"], "source manifest provenance");
  requireKeys(provenance, PROVENANCE_KEYS, "source manifest provenance", REQUIRED_PROVENANCE_KEYS);
  const runtime = asDict(provenance["runtime"], "source provenance runtime");
  requireKeys(runtime, RUNTIME_KEYS, "source provenance runtime", [...RUNTIME_KEYS]);
  if ("model" in provenance) {
    const model = asDict(provenance["model"], "source provenance model");
    requireKeys(model, MODEL_KEYS, "source provenance model", ["name"]);
    if ("sampling" in model) {
      requireKeys(
        asDict(model["sampling"], "source provenance sampling"),
        SAMPLING_KEYS,
        "source provenance sampling",
      );
    }
  }
  requireKeys(
    asDict(manifest["viewer"], "source manifest viewer"),
    VIEWER_KEYS,
    "source manifest viewer",
    [...VIEWER_KEYS],
  );
  if (provenance["complete"] !== true) {
    throw new PublicationError("publication requires complete compiler provenance (exact IR binding)");
  }
  const irSha = workflow["ir_sha256"];
  if (typeof irSha !== "string" || !SHA256_RE.test(irSha)) {
    throw new PublicationError("publication source manifest has no valid ir_sha256");
  }
  const traceId = manifest["trace_id"];
  if (typeof traceId !== "string" || !TRACE_ID_RE.test(traceId)) {
    throw new PublicationError("publication source manifest has an invalid trace_id");
  }
  const createdAt = asString(manifest["created_at"], "source created_at");
  return {
    manifest,
    source: {
      archive: "",
      trace_id: traceId,
      content_identity: "",
      profile: SOURCE_PROFILE,
      status,
      created_at: createdAt,
    },
  };
}

function readLedger(entries: Record<string, Uint8Array>, sourceTraceId: string): Record<string, unknown>[] {
  const text = new TextDecoder().decode(entries[EVENTS_PATH]);
  const records: Record<string, unknown>[] = [];
  text.split("\n").forEach((line, index) => {
    if (line.trim() === "") return;
    let parsed: unknown;
    try {
      parsed = parseJsonStrict(line);
    } catch (error) {
      throw new PublicationError(
        `publication source ledger line ${index + 1} is unparsable: ${String(error)}`,
      );
    }
    const record = asDict(parsed, `source ledger line ${index + 1}`);
    const kind = record["kind"];
    if (typeof kind !== "string" || !LEDGER_KINDS.has(kind)) {
      throw new PublicationError(
        `publication source ledger line ${index + 1} has unknown kind ${reprLike(kind)}`,
      );
    }
    if (record["run_id"] !== sourceTraceId) {
      throw new PublicationError(
        `publication source ledger line ${index + 1} is not bound to its manifest trace_id`,
      );
    }
    if (record["_omit"] !== undefined && record["_omit"] !== null) {
      throw new PublicationError(
        `publication source ledger line ${index + 1} carries an internal omit marker`,
      );
    }
    records.push(record);
  });
  if (records.length === 0) throw new PublicationError("publication source ledger is empty");
  return records;
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

class ProjectionState {
  readonly options: NormalizedOptions;
  readonly pathRefs = new Map<string, string>();
  toolNamesRemoved = 0;
  toolNamesRetained = 0;
  pathsOpaque = 0;
  redactionMarkers = 0;
  annotations = 0;

  constructor(options: NormalizedOptions) {
    this.options = options;
  }

  pathRef(path: string): string {
    const existing = this.pathRefs.get(path);
    if (existing !== undefined) return existing;
    const ref = `path-${this.pathRefs.size + 1}`;
    this.pathRefs.set(path, ref);
    return ref;
  }
}

function countMarkers(node: unknown): number {
  if (node === null || typeof node !== "object") return 0;
  if (Array.isArray(node)) {
    return (node as unknown[]).reduce<number>((total, item) => total + countMarkers(item), 0);
  }
  const mapping = node as Record<string, unknown>;
  if ("$redacted" in mapping) return 1;
  return Object.values(mapping).reduce<number>((total, item) => total + countMarkers(item), 0);
}

function projectArgs(
  args: Record<string, unknown>,
  state: ProjectionState,
  redacted: string[],
): Record<string, unknown> {
  // Unrecognized argument names were already reported by validateRecordShape
  // and are dropped here rather than refused (args names are open data).
  const projected: Record<string, unknown> = {};
  for (const key of Object.keys(args)) {
    if (PUBLIC_ARGS_KEYS.has(key)) projected[key] = args[key];
  }
  const path = projected["path"];
  if (typeof path === "string" && !state.options.keep_relative_paths) {
    delete projected["path"];
    projected["path_ref"] = state.pathRef(path);
    redacted.push("/args/path");
    state.pathsOpaque += 1;
  }
  return projected;
}

function projectRecord(
  record: Record<string, unknown>,
  state: ProjectionState,
  runId: string,
): Record<string, unknown> {
  const projected: Record<string, unknown> = { ...record, run_id: runId };
  const fields = asStringList(record["redacted_fields"] ?? [], "source redacted_fields");
  validateRecordShape(record, fields);
  const toolName = projected["tool_name"];
  if (typeof toolName === "string") {
    if (state.options.allow_tool_names.includes(toolName)) {
      state.toolNamesRetained += 1;
    } else {
      delete projected["tool_name"];
      fields.push("/tool_name");
      state.toolNamesRemoved += 1;
    }
  }
  const args = projected["args"];
  if (args !== null && typeof args === "object" && !Array.isArray(args)) {
    projected["args"] = projectArgs(args as Record<string, unknown>, state, fields);
  }
  if (fields.length > 0) {
    projected["redacted_fields"] = [...new Set(fields)].sort();
  }
  if (projected["kind"] === "annotation") state.annotations += 1;
  state.redactionMarkers += countMarkers(projected);
  return projected;
}

function projectGraph(graphRaw: unknown): Record<string, unknown> {
  const graph = asDict(graphRaw, "source workflow graph");
  requireKeys(graph, GRAPH_KEYS, "source workflow graph", [...GRAPH_KEYS]);
  if (graph["format"] !== GRAPH_FORMAT) {
    throw new PublicationError(
      `publication source workflow graph format ${reprLike(graph["format"])} is unsupported`,
    );
  }
  const nodes = asList(graph["nodes"], "source graph nodes").map((nodeRaw) => {
    const node = asDict(nodeRaw, "source graph node");
    requireKeys(node, NODE_KEYS, "source graph node", ["id", "execution"]);
    const writes = asList(node["writes"] ?? [], "source node writes").map((writeRaw) => {
      const write = asDict(writeRaw, "source node write");
      requireKeys(write, WRITE_KEYS, "source node write", ["name", "type", "optional"]);
      return {
        name: asString(write["name"], "node write name"),
        type: asString(write["type"], "node write type"),
        optional: write["optional"] === true,
      };
    });
    return {
      id: asString(node["id"], "node id"),
      execution: asString(node["execution"], "node execution"),
      capabilities: asStringList(node["capabilities"] ?? [], "source node capabilities"),
      writes,
    };
  });
  const transitions = asList(graph["transitions"], "source graph transitions").map((raw) => {
    const transition = asDict(raw, "source graph transition");
    requireKeys(transition, TRANSITION_KEYS, "source graph transition", [...TRANSITION_KEYS]);
    return {
      from: asString(transition["from"], "transition from"),
      to: asString(transition["to"], "transition to"),
      priority: transition["priority"],
      guard_kind: asString(transition["guard_kind"], "transition guard_kind"),
    };
  });
  const policies = asList(graph["policies"], "source graph policies").map((raw) => {
    const policy = asDict(raw, "source graph policy");
    requireKeys(policy, POLICY_KEYS, "source graph policy", ["ref", "kind", "trigger_capability"]);
    const entry: Record<string, unknown> = {
      ref: asString(policy["ref"], "policy ref"),
      kind: asString(policy["kind"], "policy kind"),
      trigger_capability: asString(policy["trigger_capability"], "policy trigger capability"),
    };
    if ("required_capabilities" in policy) {
      entry["required_capabilities"] = asStringList(
        policy["required_capabilities"],
        "policy required_capabilities",
      );
    }
    return entry;
  });
  return {
    format: GRAPH_FORMAT,
    workflow_id: asString(graph["workflow_id"], "graph workflow_id"),
    entry: asString(graph["entry"], "graph entry"),
    exits: asStringList(graph["exits"], "graph exits"),
    nodes,
    transitions,
    policies,
  };
}

async function projectionDigest(
  events: readonly Record<string, unknown>[],
  graph: Record<string, unknown>,
  options: NormalizedOptions,
): Promise<string> {
  const projectionObj = {
    format: PUBLICATION_PROJECTION_FORMAT,
    options: optionsAsDict(options),
    graph,
    events: events.map((event) => ({ ...event })),
  };
  return sha256Tag(toCanonicalBytes(projectionObj));
}

async function publicationTraceId(projectionSha256: string): Promise<string> {
  const bytes = new TextEncoder().encode(PUBLICATION_ID_DOMAIN + projectionSha256);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.slice(0, 32);
}

function buildManifest(manifest: Record<string, unknown>, traceId: string): Record<string, unknown> {
  const workflow = asDict(manifest["workflow"], "source manifest workflow");
  const provenance = asDict(manifest["provenance"], "source manifest provenance");
  const published: Record<string, unknown> = {};
  for (const key of ["complete", "frontend", "target", "compiler_version", "runtime", "model"]) {
    if (key in provenance) published[key] = provenance[key];
  }
  return {
    format: TRACE_FORMAT,
    trace_id: traceId,
    created_at: manifest["created_at"],
    status: manifest["status"],
    capture: {
      profile: "publication",
      vault_present: false,
      publication_eligible: true,
      redaction_policy: PUBLICATION_REDACTION_POLICY,
      scanner: { status: "passed", ruleset: SCANNER_RULESET },
      attested: true,
    },
    workflow: {
      id: workflow["id"],
      ir_version: workflow["ir_version"],
      ir_sha256: workflow["ir_sha256"],
      entry: workflow["entry"],
      exits: asStringList(workflow["exits"], "source workflow exits"),
    },
    provenance: published,
    integrity: { algorithm: "sha256", entry: INTEGRITY_PATH },
    viewer: { min_format: TRACE_FORMAT },
  };
}

async function buildEntries(
  manifestObj: Record<string, unknown>,
  graph: Record<string, unknown>,
  events: readonly Record<string, unknown>[],
  summary: Record<string, unknown>,
): Promise<Record<string, Uint8Array>> {
  const eventsBytes = ledgerBytes(events);
  const summaryBytes = toCanonicalBytes(summary);
  const payloads: Record<string, Uint8Array> = {
    [MANIFEST_PATH]: toCanonicalBytes(manifestObj),
    [GRAPH_PATH]: toCanonicalBytes(graph),
    [EVENTS_PATH]: eventsBytes,
    [SUMMARY_PATH]: summaryBytes,
  };
  const paths = Object.keys(payloads).sort();
  const index: Record<string, unknown>[] = [];
  for (const path of paths) {
    const data = payloads[path];
    index.push({
      path,
      media_type: path.endsWith(".ndjson") ? "application/x-ndjson" : "application/json",
      uncompressed_bytes: data.length,
      sha256: await sha256Tag(data),
    });
  }
  const identity = {
    format: CONTENT_IDENTITY_FORMAT,
    entries: index.map((entry) => ({
      path: entry["path"],
      sha256: entry["sha256"],
      uncompressed_bytes: entry["uncompressed_bytes"],
    })),
  };
  const integrity = {
    format: "nemoir.trace.integrity/0.1",
    algorithm: "sha256",
    entries: index,
    content_identity: await sha256Tag(toCanonicalBytes(identity)),
  };
  payloads[INTEGRITY_PATH] = toCanonicalBytes(integrity);
  return payloads;
}

async function buildSummary(
  records: readonly Record<string, unknown>[],
  eventsBytes: Uint8Array,
  sourceSummary: Record<string, unknown> | null,
): Promise<Record<string, unknown>> {
  const kinds: Record<string, number> = {};
  const visits = new Set<string>();
  for (const record of records) {
    const kind = String(record["kind"] ?? "?");
    kinds[kind] = (kinds[kind] ?? 0) + 1;
    const visit = record["stage_visit_id"];
    if (typeof visit === "string") visits.add(visit);
  }
  const summary: Record<string, unknown> = {
    format: SUMMARY_FORMAT,
    events_sha256: await sha256Tag(eventsBytes),
    event_count: records.length,
    stage_visit_count: visits.size,
    duration_ms: 0,
    counts_by_kind: kinds,
    annotations_dropped: 0,
    annotation_warnings: [],
  };
  if (sourceSummary !== null) {
    const duration = sourceSummary["duration_ms"];
    if (typeof duration === "number" && Number.isInteger(duration) && duration >= 0) {
      summary["duration_ms"] = duration;
    }
    const dropped = sourceSummary["annotations_dropped"];
    if (typeof dropped === "number" && Number.isInteger(dropped) && dropped >= 0) {
      summary["annotations_dropped"] = dropped;
    }
    const warnings = sourceSummary["annotation_warnings"];
    if (Array.isArray(warnings)) {
      summary["annotation_warnings"] = (warnings as unknown[]).map((item) => String(item));
    }
  }
  return summary;
}

/** NDJSON bytes for projected records: canonical JSON plus one newline each. */
function ledgerBytes(records: readonly Record<string, unknown>[]): Uint8Array {
  const newline = new TextEncoder().encode("\n");
  return concat(records.flatMap((record) => [toCanonicalBytes(record), newline]));
}

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function contentIdentity(entries: Record<string, Uint8Array>): string {
  const integrity = asDict(
    parseJsonStrict(new TextDecoder().decode(entries[INTEGRITY_PATH])),
    "publication integrity",
  );
  return asString(integrity["content_identity"], "integrity content_identity");
}

// ---------------------------------------------------------------------------
// Scan (project for review)
// ---------------------------------------------------------------------------

export async function scanPublication(
  source: string,
  sourceBytes: Uint8Array,
  options?: PublicationOptions,
  archiveName?: string,
): Promise<PublicationProjection> {
  const active = normalizeOptions(options);
  const entries = readArchiveEntries(sourceBytes);
  const verification: VerificationReport = await verifyArchive(sourceBytes);
  if (!verification.ok) {
    const detail = verification.errors.slice(0, 5).join("; ") || "verification failed";
    throw new PublicationError(`publication source does not verify: ${detail}`);
  }
  const { manifest, source: facts } = validateManifest(entries);
  const records = readLedger(entries, facts.trace_id);
  const graph = projectGraph(parseJsonStrict(new TextDecoder().decode(entries[GRAPH_PATH])));
  const state = new ProjectionState(active);
  const reviewed = records.map((record) => projectRecord(record, state, facts.trace_id));
  const digest = await projectionDigest(reviewed, graph, active);
  const traceId = await publicationTraceId(digest);
  const projected: Record<string, unknown>[] = reviewed.map((record) => ({
    ...record,
    run_id: traceId,
  }));
  let sourceSummary: Record<string, unknown> | null = null;
  if (SUMMARY_PATH in entries) {
    try {
      const parsed: unknown = parseJsonStrict(new TextDecoder().decode(entries[SUMMARY_PATH]));
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        sourceSummary = parsed as Record<string, unknown>;
      }
    } catch {
      sourceSummary = null;
    }
  }
  const eventsBytes = ledgerBytes(projected);
  const summary = await buildSummary(projected, eventsBytes, sourceSummary);
  const payloads = await buildEntries(buildManifest(manifest, traceId), graph, projected, summary);
  const findings = scanCleartextEntries(payloads);
  const visits = new Set<string>();
  for (const record of projected) {
    const visit = record["stage_visit_id"];
    if (typeof visit === "string") visits.add(visit);
  }
  return {
    entries: payloads,
    trace_id: traceId,
    projection_sha256: digest,
    content_identity: contentIdentity(payloads),
    source: {
      archive: archiveName ?? basename(source),
      trace_id: facts.trace_id,
      content_identity: verification.contentIdentity ?? "",
      profile: facts.profile,
      status: facts.status,
      created_at: facts.created_at,
    },
    stats: {
      event_count: projected.length,
      stage_visit_count: visits.size,
      tool_names_removed: state.toolNamesRemoved,
      tool_names_retained: state.toolNamesRetained,
      paths_opaque: state.pathsOpaque,
      redaction_markers: state.redactionMarkers,
      annotations: state.annotations,
    },
    findings,
    scanned_entries: Object.keys(payloads).sort(),
    options: active,
  };
}

function basename(path: string): string {
  const parts = path.split(/[/\\]/);
  return parts[parts.length - 1] ?? path;
}

export function publicationReportPath(archive: string): string {
  return `${archive}.publication-report.json`;
}

export function publicationReport(
  projection: PublicationProjection,
  attested: boolean,
  attestation: PublicationAttestation | null,
): Record<string, unknown> {
  const publication: Record<string, unknown> = {
    trace_id: projection.trace_id,
    projection_sha256: projection.projection_sha256,
    content_identity: projection.content_identity,
    redaction_policy: PUBLICATION_REDACTION_POLICY,
    vault_present: false,
    entries: [...projection.scanned_entries],
  };
  return {
    format: PUBLICATION_REPORT_FORMAT,
    source: { ...projection.source },
    publication,
    options: optionsAsDict(projection.options),
    scan: {
      ruleset: SCANNER_RULESET,
      status: projection.findings.length === 0 ? "passed" : "failed",
      findings: [...projection.findings],
      findings_count: projection.findings.length,
    },
    stats: { ...projection.stats },
    disclosure: {
      source_profile: projection.source.profile,
      vault_copied: false,
      identifiers_retained: [
        "workflow_id",
        "stage_ids",
        "capabilities",
        "declared_output_field_names",
      ],
      limits: [
        "Publication is a fresh projection of an audit ledger, not a re-encoding of a private run.",
        "Paths are opaque path-N references unless a reviewer opted into relative paths.",
        "Tool names are dropped unless a reviewer allowlisted them.",
        "Redaction reduces risk; reviewed identifiers, declared field names, and approved " +
          "scalar metrics may still be sensitive. Human review is mandatory.",
      ],
    },
    attested,
    attestation: attestation === null ? null : attestationDocument(attestation),
  };
}

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

export function buildAttestation(
  projection: PublicationProjection,
  options: PublicationOptions,
  fields: {
    reviewer: string;
    license: string;
    consent: string;
    reviewed_at?: string;
  },
): PublicationAttestation {
  const active = normalizeOptions(options);
  return {
    ...validateReview(fields),
    source_content_identity: projection.source.content_identity,
    source_trace_id: projection.source.trace_id,
    projection_sha256: projection.projection_sha256,
    options: optionsAsDict(active),
  };
}

function validateReview(fields: {
  reviewer: string;
  license: string;
  consent: string;
  reviewed_at?: string;
}): { reviewer: string; reviewed_at: string; license: string; consent: string } {
  const reviewer = fields.reviewer.trim();
  if (reviewer === "" || reviewer.length > MAX_REVIEWER_LEN) {
    throw new PublicationError(
      `attestation requires a reviewer name (1-${MAX_REVIEWER_LEN} characters)`,
    );
  }
  const license = fields.license.trim();
  if (license === "" || license.length > MAX_LICENSE_LEN) {
    throw new PublicationError(
      `attestation requires a license identifier (1-${MAX_LICENSE_LEN} characters)`,
    );
  }
  const consent = fields.consent.split(/\s+/).filter((part) => part !== "").join(" ");
  if (consent === "" || consent.length > MAX_CONSENT_LEN) {
    throw new PublicationError(
      `attestation requires a consent statement (1-${MAX_CONSENT_LEN} characters)`,
    );
  }
  return {
    reviewer,
    reviewed_at: fields.reviewed_at ?? new Date().toISOString(),
    license,
    consent,
  };
}

/**
 * Build an attestation from the disclosure report a human just reviewed.
 *
 * Deriving the digests from the report (rather than accepting them on the
 * command line) means a reviewer cannot attest a projection they have not been
 * shown, and a failed scan can never be attested.
 */
export function attestationFromReport(
  report: unknown,
  fields: { reviewer: string; license: string; consent: string; reviewed_at?: string },
): PublicationAttestation {
  const node = asDict(report, "report");
  if (node["format"] !== PUBLICATION_REPORT_FORMAT) {
    throw new PublicationError(
      `unsupported disclosure report format ${reprLike(node["format"])}`,
    );
  }
  const scan = asDict(node["scan"], "report scan");
  if (scan["status"] !== "passed") {
    throw new PublicationError(
      `report scan did not pass (${String(scan["findings_count"] ?? 0)} finding(s)); ` +
        "refusal cannot be attested",
    );
  }
  const source = asDict(node["source"], "report source");
  const publication = asDict(node["publication"], "report publication");
  const optionsNode = asDict(node["options"], "report options");
  requireKeys(optionsNode, OPTIONS_KEYS, "report options", [...OPTIONS_KEYS]);
  if (typeof optionsNode["keep_relative_paths"] !== "boolean") {
    throw new PublicationError("report options keep_relative_paths must be a boolean");
  }
  const digest = publication["projection_sha256"];
  if (typeof digest !== "string" || !SHA256_RE.test(digest)) {
    throw new PublicationError("report projection_sha256 is invalid");
  }
  const options = normalizeOptions({
    allow_tool_names: asStringList(optionsNode["allow_tool_names"], "report allow_tool_names"),
    keep_relative_paths: optionsNode["keep_relative_paths"],
  });
  return {
    ...validateReview(fields),
    source_content_identity: asString(source["content_identity"], "report source content_identity"),
    source_trace_id: asString(source["trace_id"], "report source trace_id"),
    projection_sha256: digest,
    options: optionsAsDict(options),
  };
}

export function attestationFromDict(data: unknown): PublicationAttestation {
  const node = asDict(data, "attestation");
  if (node["format"] !== PUBLICATION_ATTESTATION_FORMAT) {
    throw new PublicationError(`unsupported attestation format ${reprLike(node["format"])}`);
  }
  requireKeys(node, ATTESTATION_KEYS, "attestation", [...ATTESTATION_KEYS]);
  const source = asDict(node["source"], "attestation source");
  requireKeys(
    source,
    ATTESTATION_SOURCE_KEYS,
    "attestation source",
    [...ATTESTATION_SOURCE_KEYS],
  );
  const projection = asDict(node["projection"], "attestation projection");
  requireKeys(
    projection,
    ATTESTATION_PROJECTION_KEYS,
    "attestation projection",
    [...ATTESTATION_PROJECTION_KEYS],
  );
  const optionsNode = asDict(node["options"], "attestation options");
  requireKeys(optionsNode, OPTIONS_KEYS, "attestation options", [...OPTIONS_KEYS]);
  if (typeof optionsNode["keep_relative_paths"] !== "boolean") {
    throw new PublicationError("attestation options keep_relative_paths must be a boolean");
  }
  const digest = projection["sha256"];
  if (typeof digest !== "string" || !SHA256_RE.test(digest)) {
    throw new PublicationError("attestation projection sha256 is invalid");
  }
  const options = normalizeOptions({
    allow_tool_names: asStringList(
      optionsNode["allow_tool_names"],
      "attestation allow_tool_names",
    ),
    keep_relative_paths: optionsNode["keep_relative_paths"],
  });
  return {
    reviewer: asString(node["reviewer"], "attestation reviewer").trim(),
    reviewed_at: asString(node["reviewed_at"], "attestation reviewed_at").trim(),
    license: asString(node["license"], "attestation license").trim(),
    consent: asString(node["consent"], "attestation consent").trim(),
    source_content_identity: asString(
      source["content_identity"],
      "attestation source content_identity",
    ).trim(),
    source_trace_id: asString(source["trace_id"], "attestation source trace_id").trim(),
    projection_sha256: digest,
    options: optionsAsDict(options),
  };
}

export function attestationDocument(attestation: PublicationAttestation): Record<string, unknown> {
  return {
    format: PUBLICATION_ATTESTATION_FORMAT,
    source: {
      content_identity: attestation.source_content_identity,
      trace_id: attestation.source_trace_id,
    },
    projection: { sha256: attestation.projection_sha256 },
    options: attestation.options,
    reviewer: attestation.reviewer,
    reviewed_at: attestation.reviewed_at,
    license: attestation.license,
    consent: attestation.consent,
  };
}

// ---------------------------------------------------------------------------
// Prepare (write) path
// ---------------------------------------------------------------------------

export async function preparePublication(
  source: string,
  sourceBytes: Uint8Array,
  destination: string,
  attestation: PublicationAttestation,
): Promise<{
  readonly bytes: Uint8Array;
  readonly projection: PublicationProjection;
  readonly result: PublicationResult;
}> {
  const projection = await scanPublication(
    source,
    sourceBytes,
    attestation.options,
    basename(source),
  );
  if (projection.findings.length > 0) {
    throw new PublicationError(
      `publication scanner blocked export with ${projection.findings.length} finding(s): ` +
        projection.findings.slice(0, 5).join("; "),
    );
  }
  if (projection.projection_sha256 !== attestation.projection_sha256) {
    throw new PublicationError(
      "attestation does not cover this projection (projection_sha256 mismatch); " +
        "re-run scan-publication and attest again",
    );
  }
  if (projection.source.content_identity !== attestation.source_content_identity) {
    throw new PublicationError(
      "attestation source content identity does not match the source archive",
    );
  }
  if (projection.source.trace_id !== attestation.source_trace_id) {
    throw new PublicationError("attestation source trace id does not match the source archive");
  }
  const bytes = writeArchive(projection.entries);
  return {
    bytes,
    projection,
    result: {
      destination,
      trace_id: projection.trace_id,
      projection_sha256: projection.projection_sha256,
      content_identity: projection.content_identity,
      compressed_bytes: bytes.length,
      source: projection.source,
      stats: projection.stats,
    },
  };
}

/** Serialize one JSON document the way both CLIs write sidecars. */
export function serializeDocument(document: unknown): Uint8Array {
  return new TextEncoder().encode(`${canonicalStringify(document)}\n`);
}
