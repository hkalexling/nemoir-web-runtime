/**
 * NemoIR Web Runtime — NemoTrace audit recorder and single-file archive.
 *
 * TypeScript port of `python/nemoir-runtime/src/nemoir_runtime/trace.py`
 * (Phase 1). Turns a run's live `WorkflowEvent` stream plus recorder
 * semantic hooks into one portable `.nemotrace` ZIP artifact: a redacted
 * public ledger, a safe workflow-graph projection, a derived summary cache,
 * and an integrity index bound to an exact compiled-IR fingerprint.
 *
 * Security model (`docs/trace/redaction-policy.md`): allowlist projection
 * at capture time; `audit` is the only Phase 1 profile; credentials never
 * enter the ledger; the final cleartext scanner blocks finalization on any
 * unresolved finding (locations only, never values).
 *
 * Environment notes:
 * - No Node imports: works in browsers, workers, and Node alike.
 * - Hashing is async (`crypto.subtle`), so finalization/verification are
 *   async. Canonical stringification itself is synchronous.
 * - `finishRun()` resolves to ZIP **bytes**. Persistence is the host's job:
 *   tests/Node write files, browser apps wrap them in a `Blob` for
 *   user-gesture export. IndexedDB staging arrives with the viewer (Phase 2).
 */

import { canonicalStringify, parseJsonStrict } from "./canonical.js";
import type { WorkflowEvent } from "./events.js";
import type { WorkflowManifest } from "./manifest.js";
import { unzipSync, zipSync } from "fflate";

// ---------------------------------------------------------------------------
// Format constants (mirror docs/trace/schema/README.md)
// ---------------------------------------------------------------------------

export const TRACE_FORMAT = "nemoir.trace/0.1";
export const GRAPH_FORMAT = "nemoir.trace.workflow-graph/0.1";
export const SUMMARY_FORMAT = "nemoir.trace.summary/0.1";
export const CONTENT_IDENTITY_FORMAT = "nemoir.trace.content-identity/0.1";
export const PROVENANCE_FORMAT = "nemoir.trace-provenance/0.1";
export const REDACTION_POLICY = "audit-v1";
export const SCANNER_RULESET = "secrets-v1";
export const RUNTIME_NAME = "nemoir-runtime";
// Keep in sync with package.json (enforced by trace.test.ts).
export const RUNTIME_VERSION = "0.5.0";

export const MANIFEST_PATH = "manifest.json";
export const GRAPH_PATH = "public/workflow.graph.json";
export const EVENTS_PATH = "public/events.ndjson";
export const SUMMARY_PATH = "public/summary.json";
export const INTEGRITY_PATH = "integrity.json";
export const AUDIT_ENTRY_PATHS = [MANIFEST_PATH, GRAPH_PATH, EVENTS_PATH, SUMMARY_PATH] as const;

// Deterministic ZIP profile (matches the Phase 0 fixture assembly).
const ZIP_EPOCH = /* @__PURE__ */ new Date("1980-01-01T00:00:00Z");
const ZIP_DEFLATE_LEVEL = 6;

// Reader limits: local audit/replay viewer budget from schema/README.md §2.
export const LIMIT_COMPRESSED_BYTES = 64 * 1024 * 1024;
export const LIMIT_UNCOMPRESSED_TOTAL_BYTES = 256 * 1024 * 1024;
export const LIMIT_UNCOMPRESSED_ENTRY_BYTES = 192 * 1024 * 1024;
export const LIMIT_EVENT_COUNT = 500_000;
export const LIMIT_COMPRESSION_RATIO = 200;

// JS safe-integer bounds for portable trace semantics (I-JSON).
export const MAX_SAFE_INT = 9007199254740991;
export const MIN_SAFE_INT = -9007199254740991;

// Allowlist bounds (audit-v1 field shapes and redaction-loop guards).
const ERROR_SUFFIX_LEN = 5;
const MAX_ERROR_CODE_LEN = 64;
const MAX_TOOL_NAME_LEN = 128;
const MAX_METHOD_LEN = 16;
const MAX_CATEGORY_LEN = 64;
const MIN_SECRET_LEN = 8;
const MAX_MASK_PASSES = 8;

export class TraceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TraceError";
  }
}

// ---------------------------------------------------------------------------
// Host-supplied configuration
// ---------------------------------------------------------------------------

export interface ModelDescriptor {
  readonly name: string;
  readonly apiMode?: string;
  readonly temperature?: number;
  readonly maxTokens?: number;
}

export interface HostProvenance {
  readonly frontend: string;
  readonly target: string;
  readonly compilerVersion: string;
  readonly irVersion: string;
  /** Null marks provenance incomplete: no IR binding may be claimed. */
  readonly irSha256: string | null;
}

export function incompleteProvenance(): HostProvenance {
  return {
    frontend: "manual",
    target: "manual",
    compilerVersion: "unknown",
    irVersion: "0.1",
    irSha256: null,
  };
}

export interface TraceConfig {
  readonly profile?: string;
  readonly provenance?: HostProvenance;
  readonly model?: ModelDescriptor;
  /** Alias (e.g. "$workspace") -> local root the alias stands for. */
  readonly pathAliases?: Readonly<Record<string, string>>;
  /** Aliases whose alias-relative segments may appear in cleartext. */
  readonly safePathAliases?: ReadonlySet<string> | readonly string[];
  /** Exact `"StageId.field"` stage outputs allowed as public metrics. */
  readonly approvedMetrics?: ReadonlySet<string> | readonly string[];
  /** Known credential *values* for echo defense-in-depth. Never serialized. */
  readonly secrets?: readonly string[];
  /** Test hook: fixed trace id for byte-identical fixtures. */
  readonly traceId?: string;
  /** Test hook: fixed clock for byte-identical fixtures. */
  readonly clock?: () => Date;
}

export interface VerificationReport {
  readonly ok: boolean;
  readonly contentIdentity: string | null;
  readonly warnings: readonly string[];
  readonly errors: readonly string[];
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return `sha256:${[...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

export function generateTraceId(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID().replace(/-/g, "");
  }
  return Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
}

function camelToSnake(name: string): string {
  return name
    .replace(/(.)([A-Z][a-z]+)/g, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase();
}

/** Map an error to a (stableCode, typeName) pair. Messages never escape. */
export function stableError(exc: unknown): { code: string; typeName: string } {
  let typeName =
    exc !== null && exc !== undefined && typeof (exc as { constructor?: unknown }).constructor === "function"
      ? String((exc as { constructor: { name?: unknown } }).constructor.name ?? "UnknownError")
      : "UnknownError";
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(typeName)) typeName = "UnknownError";
  const stem =
    typeName.endsWith("Error") && typeName.length > ERROR_SUFFIX_LEN
      ? typeName.slice(0, -ERROR_SUFFIX_LEN)
      : typeName;
  let code = camelToSnake(stem);
  if (!/^[a-z][a-z0-9_]*$/.test(code) || code.length > MAX_ERROR_CODE_LEN) {
    code = "unknown_error";
  }
  return { code, typeName };
}

type RedactionReason =
  | "credential"
  | "private_content"
  | "personal_data"
  | "absolute_path"
  | "reasoning"
  | "unsafe_error"
  | "unapproved_field";

function valueType(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return "number";
  if (typeof value === "string") return "string";
  if (value instanceof Uint8Array) return "binary";
  if (Array.isArray(value)) return "array";
  return "object";
}

function resultTypeSlug(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return "number";
  if (typeof value === "string") return "string";
  if (value instanceof Uint8Array || value instanceof ArrayBuffer) return "binary";
  if (Array.isArray(value)) return "array";
  return "object";
}

// ---------------------------------------------------------------------------
// Secret registry + cleartext scanner (secrets-v1)
// ---------------------------------------------------------------------------

class SecretRegistry {
  private readonly long: ReadonlySet<string>;
  private readonly short: ReadonlySet<string>;
  private readonly shortPatterns: readonly RegExp[];

  constructor(secrets: readonly string[] = []) {
    const long = new Set<string>();
    const short = new Set<string>();
    const shortPatterns: RegExp[] = [];
    for (const secret of secrets) {
      if (!secret) continue;
      if (secret.length >= MIN_SECRET_LEN) {
        long.add(secret);
        long.add(`Bearer ${secret}`);
      } else {
        short.add(secret);
        shortPatterns.push(new RegExp(`(?<![A-Za-z0-9_\\-])${escapeRegExp(secret)}(?![A-Za-z0-9_\\-])`));
        const bearer = `Bearer ${secret}`;
        short.add(bearer);
        shortPatterns.push(new RegExp(`(?<![A-Za-z0-9_\\-])${escapeRegExp(bearer)}(?![A-Za-z0-9_\\-])`));
      }
    }
    this.long = long;
    this.short = short;
    this.shortPatterns = shortPatterns;
  }

  findHit(text: string): boolean {
    for (const value of this.long) {
      if (text.includes(value)) return true;
    }
    if (this.short.size === 0) return false;
    let maybe = false;
    for (const s of this.short) {
      if (text.includes(s)) { maybe = true; break; }
    }
    if (!maybe) return false;
    for (const pattern of this.shortPatterns) {
      if (pattern.test(text)) return true;
    }
    return false;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const SECRET_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ["provider_key", /sk-(?:ant|nemoir)[A-Za-z0-9\-_]{8,}/],
  ["provider_key", /sk-[A-Za-z0-9\-_]{16,}/],
  ["github_token", /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{8,}/],
  ["github_token", /github_pat_[A-Za-z0-9_\-]{8,}/],
  ["cloud_key", /AKIA[0-9A-Z]{16}/],
  ["cloud_key", /xox[bap]-[A-Za-z0-9\-]{8,}/],
  ["auth_header", /Bearer\s+\S{8,}/],
  ["auth_header", /Basic\s+[A-Za-z0-9+/=]{8,}/],
  ["private_key", /-----BEGIN .*PRIVATE KEY/],
  ["credential_url", /:\/\/[^/\s]*:[^/\s]*@/],
  ["credential_query", /[?&#](?:api[_-]?key|token|secret|password)=[^&#\s]*/i],
  ["home_path", /\/home\/[^/\s]*/],
  ["home_path", /\/Users\/[^/\s]*/],
  ["home_path", /C:[\\/]Users[\\/][^\\/\\s]*/],
  ["home_path", /\\\\[A-Za-z0-9_.$\-]+\\/],
];

const CREDENTIAL_RULES = new Set([
  "provider_key",
  "github_token",
  "cloud_key",
  "auth_header",
  "private_key",
  "credential_url",
  "credential_query",
]);

const PROHIBITED_KEYS = new Set([
  "api_key",
  "authorization",
  "cookie",
  "extra_headers",
  "reasoning",
  "traceback",
  "stdout",
  "stderr",
]);

interface Finding {
  readonly rule: string;
  readonly pointer: string;
}

function escapePointerSegment(segment: string): string {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}

function* iterStrings(node: unknown, pointer: string): Generator<[string, string | null, string | null]> {
  if (typeof node === "string") {
    yield [pointer, null, node];
  } else if (node !== null && typeof node === "object" && !Array.isArray(node)) {
    for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
      const child = `${pointer}/${escapePointerSegment(key)}`;
      yield [child, key, typeof val === "string" ? val : null];
      if (typeof val !== "string") yield* iterStrings(val, child);
    }
  } else if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      yield* iterStrings(node[i], `${pointer}/${i}`);
    }
  }
}

function scanStrings(node: unknown, pointer: string, registry: SecretRegistry): Finding[] {
  const findings: Finding[] = [];
  for (const [childPointer, key, value] of iterStrings(node, pointer)) {
    if (key !== null && PROHIBITED_KEYS.has(key)) {
      findings.push({ rule: "prohibited_field", pointer: childPointer });
      continue;
    }
    if (value === null) continue;
    if (registry.findHit(value)) {
      findings.push({ rule: "registered_secret", pointer: childPointer });
      continue;
    }
    for (const [rule, pattern] of SECRET_PATTERNS) {
      // Fresh lastIndex for global-free patterns is automatic (no /g flag).
      if (pattern.test(value)) {
        findings.push({ rule, pointer: childPointer });
        break;
      }
    }
  }
  return findings;
}

// Pointers whose values may be replaced by a redaction marker without
// breaking the writer schema. Anything else forces record omission.
const MASKABLE_EXACT = new Set(["/text", "/result"]);
const MASKABLE_PREFIXES = ["/output/", "/annotation/payload/"];
const MASKABLE_ARGS = new Set([
  "/args/content",
  "/args/key",
  "/args/value",
  "/args/code",
  "/args/input",
  "/args/headers",
  "/args/body",
  "/args/question",
  "/args/message",
  "/args/options",
]);

function isMaskable(pointer: string): boolean {
  return (
    MASKABLE_EXACT.has(pointer) ||
    MASKABLE_PREFIXES.some((prefix) => pointer.startsWith(prefix)) ||
    MASKABLE_ARGS.has(pointer)
  );
}

function unescapePointerSegment(segment: string): string {
  return segment.replace(/~1/g, "/").replace(/~0/g, "~");
}

function hasUnsafeInt(node: unknown): boolean {
  if (typeof node === "number") {
    return Number.isInteger(node) && !Number.isSafeInteger(node);
  }
  if (node !== null && typeof node === "object") {
    if (Array.isArray(node)) {
      return (node as unknown[]).some(hasUnsafeInt);
    }
    return Object.values(node as Record<string, unknown>).some(hasUnsafeInt);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Generated-provenance verification (generated web packages)
// ---------------------------------------------------------------------------

/**
 * Verify a generated package's `workflow.json` + `trace-provenance.json`
 * resources and return a host provenance descriptor. Any load/hash/format
 * mismatch yields *incomplete* provenance rather than throwing: the trace
 * stays honest instead of crashing the run.
 */
export async function verifyGeneratedProvenance(
  workflowJson: unknown,
  provenanceJson: unknown,
): Promise<HostProvenance> {
  const incomplete = incompleteProvenance();
  try {
    if (typeof workflowJson !== "object" || workflowJson === null) return incomplete;
    if (typeof provenanceJson !== "object" || provenanceJson === null) return incomplete;
    const claimed = provenanceJson as Record<string, unknown>;
    if (claimed.format !== PROVENANCE_FORMAT) return incomplete;
    const actual = await sha256Hex(textEncoder.encode(canonicalStringify(workflowJson)));
    if (claimed.irSha256 !== undefined) {
      // Accept both wire spellings while generated facades converge.
      if (claimed.irSha256 !== actual && claimed.ir_sha256 !== actual) return incomplete;
    } else if (claimed.ir_sha256 !== actual) {
      return incomplete;
    }
    const irSha256 =
      typeof claimed.ir_sha256 === "string"
        ? claimed.ir_sha256
        : typeof claimed.irSha256 === "string"
          ? claimed.irSha256
          : null;
    if (irSha256 === null) return incomplete;
    return {
      frontend: typeof claimed.frontend === "string" ? claimed.frontend : "unknown",
      target: typeof claimed.target === "string" ? claimed.target : "web",
      compilerVersion:
        typeof claimed.compilerVersion === "string"
          ? claimed.compilerVersion
          : typeof claimed.compiler_version === "string"
            ? (claimed.compiler_version as string)
            : "unknown",
      irVersion: typeof claimed.irVersion === "string" ? claimed.irVersion : "0.1",
      irSha256,
    };
  } catch {
    return incomplete;
  }
}

/** Build a safe model descriptor from a host adapter/spec (allowlist only). */
export function safeModelDescriptor(model: unknown): ModelDescriptor | null {
  let name: unknown = null;
  let apiMode: unknown = null;
  let temperature: unknown = null;
  let maxTokens: unknown = null;
  if (model !== null && typeof model === "object" && !Array.isArray(model)) {
    const record = model as Record<string, unknown>;
    name = record.name;
    apiMode = record.api ?? record.apiMode;
    temperature = record.temperature;
    maxTokens = record.maxTokens ?? record.max_tokens;
  } else {
    return null;
  }
  if (typeof name !== "string" || name.length === 0) return null;
  return {
    name: name.slice(0, 256),
    ...(typeof apiMode === "string" ? { apiMode: apiMode.slice(0, 64) } : {}),
    ...(typeof temperature === "number" && Number.isFinite(temperature) ? { temperature } : {}),
    ...(typeof maxTokens === "number" && Number.isInteger(maxTokens) && maxTokens >= 1
      ? { maxTokens }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// Trace recorder
// ---------------------------------------------------------------------------

export type TraceStatus = "complete" | "failed" | "interrupted";
export type TraceValue =
  | TraceRecorder
  | TraceConfig
  | (() => TraceRecorder | null)
  | null
  | undefined;

interface RecorderConfig {
  readonly profile: string;
  readonly provenance: HostProvenance;
  readonly model?: ModelDescriptor;
  readonly pathAliases: Readonly<Record<string, string>>;
  readonly safePathAliases: ReadonlySet<string>;
  readonly approvedMetrics: ReadonlySet<string>;
  readonly secrets: readonly string[];
  readonly traceId: string;
  readonly clock: () => Date;
}

function normalizeConfig(config: TraceConfig = {}): RecorderConfig {
  const profile = config.profile ?? "audit";
  if (profile !== "audit") {
    throw new TraceError(
      `unsupported trace profile '${profile}': Phase 1 supports only 'audit' ` +
        `(replay arrives in Phase 4, publication in Phase 5)`,
    );
  }
  let traceId = config.traceId ?? generateTraceId();
  if (!/^[0-9a-f]{32}$/.test(traceId)) {
    throw new TraceError(`trace id must be 32 lowercase hex, got ${JSON.stringify(traceId)}`);
  }
  const roots: Record<string, string> = {};
  for (const [alias, root] of Object.entries(config.pathAliases ?? {})) {
    if (!alias.startsWith("$")) {
      throw new TraceError(`path alias must start with '$', got ${JSON.stringify(alias)}`);
    }
    roots[alias] = root.replace(/\/+$/, "") || "/";
  }
  return {
    profile,
    provenance: config.provenance ?? incompleteProvenance(),
    model: config.model,
    pathAliases: roots,
    safePathAliases: new Set(config.safePathAliases ?? []),
    approvedMetrics: new Set(config.approvedMetrics ?? []),
    secrets: config.secrets ?? [],
    traceId,
    clock: config.clock ?? (() => new Date()),
  };
}

export class TraceRecorder {
  private readonly config: RecorderConfig;
  private readonly registry: SecretRegistry;
  private begun = false;
  private finished = false;
  private beginTime: Date | null = null;
  private manifest: WorkflowManifest | null = null;
  private readonly policyRefs = new Map<string, string>();
  private readonly events: Record<string, unknown>[] = [];
  private readonly pendingVisits = new Map<string, string[]>();
  private readonly pendingModels = new Map<string, string[]>();
  private readonly pendingTools = new Map<string, string[]>();
  private readonly openTools = new Map<string, string[]>();
  private currentVisit: string | null = null;
  private readonly modelBytes = new Map<string, number>();
  private readonly toolStartedAt = new Map<string, Date>();
  private readonly toolResultTypes = new Map<string, string>();
  private readonly toolErrors = new Map<string, { code: string; typeName: string }>();
  private readonly transitionEvidence: unknown[] = [];
  private visitCount = 0;
  private modelCount = 0;
  private toolCount = 0;
  private redactionCount = 0;
  private pathRefCount = 0;
  private readonly pathRefs = new Map<string, string>();
  private stageCompletedCount = 0;
  private eventLimitExceeded = false;

  constructor(config: TraceConfig = {}) {
    this.config = normalizeConfig(config);
    this.registry = new SecretRegistry(this.config.secrets);
  }

  get traceId(): string {
    return this.config.traceId;
  }

  /** Finalized ZIP bytes (set by finishRun; null before). Lets hosts that
   * hold the recorder retrieve the archive after `runtime.run()` returns. */
  get archiveBytes(): Uint8Array | null {
    return this.archive;
  }
  private archive: Uint8Array | null = null;

  // -- run lifecycle ---------------------------------------------------

  beginRun(manifest: WorkflowManifest): void {
    if (this.begun) {
      throw new TraceError("TraceRecorder.beginRun called twice: one recorder per run");
    }
    this.begun = true;
    this.beginTime = this.config.clock();
    this.manifest = manifest;
    manifest.policies.forEach((policy, index) => {
      if (!this.policyRefs.has(policy.id)) {
        this.policyRefs.set(policy.id, `p-${index + 1}`);
      }
    });
  }

  /** Finalize and return the deterministic `.nemotrace` ZIP bytes. */
  async finishRun(status: TraceStatus): Promise<Uint8Array> {
    if (!this.begun) throw new TraceError("TraceRecorder.finishRun without beginRun");
    if (this.finished) throw new TraceError("TraceRecorder.finishRun called twice");
    if (status !== "complete" && status !== "failed" && status !== "interrupted") {
      throw new TraceError(`unknown trace status ${JSON.stringify(status)}`);
    }
    if (this.eventLimitExceeded || this.events.length > LIMIT_EVENT_COUNT) {
      throw new TraceError(`trace event count limit exceeded (${LIMIT_EVENT_COUNT})`);
    }
    this.finished = true;
    const entries = await this.buildEntries(status);
    this.finalScan(entries);
    const bytes = writeArchive(entries);
    this.archive = bytes;
    return bytes;
  }

  // -- semantic hooks (called by the runtime at execution boundaries) ---

  /** Assign the next run-local stage-visit id for `stageId`. */
  beginStageVisit(stageId: string): string {
    this.requireBegun();
    this.visitCount += 1;
    const visitId = `s-${this.visitCount}`;
    const queue = this.pendingVisits.get(stageId) ?? [];
    queue.push(visitId);
    this.pendingVisits.set(stageId, queue);
    this.currentVisit = visitId;
    return visitId;
  }

  /** Assign the next run-local model-call id. */
  beginModelCall(_stageId = "", stageVisitId?: string): string {
    this.requireBegun();
    this.modelCount += 1;
    const callId = `m-${this.modelCount}`;
    const visit = stageVisitId ?? this.currentVisit ?? "";
    const queue = this.pendingModels.get(visit) ?? [];
    queue.push(callId);
    this.pendingModels.set(visit, queue);
    return callId;
  }

  /** Record safe model-response facts (counts only, never text). */
  recordModelResponse(modelCallId: string, facts: { responseBytes?: number; toolCallCount?: number } = {}): void {
    this.requireBegun();
    this.modelBytes.set(modelCallId, Math.max(0, Math.trunc(facts.responseBytes ?? 0)));
  }

  /** Assign the next run-local tool-call id. */
  beginToolCall(_stageId = "", stageVisitId?: string): string {
    this.requireBegun();
    this.toolCount += 1;
    const callId = `t-${this.toolCount}`;
    const visit = stageVisitId ?? this.currentVisit ?? "";
    const queue = this.pendingTools.get(visit) ?? [];
    queue.push(callId);
    this.pendingTools.set(visit, queue);
    this.toolStartedAt.set(callId, this.config.clock());
    return callId;
  }

  /** Note a tool result's safe type facts (the value stays private). */
  recordToolResult(toolCallId: string, result: unknown): void {
    this.requireBegun();
    this.toolErrors.delete(toolCallId);
    this.toolResultTypes.set(toolCallId, resultTypeSlug(result));
  }

  /** Capture a tool failure's stable error taxonomy (no message). */
  recordToolError(toolCallId: string, exc: unknown): void {
    this.requireBegun();
    this.toolErrors.set(toolCallId, stableError(exc));
  }

  /**
   * Retain guard-evaluation evidence for future semantic verification.
   * Phase 1 keeps this in memory only; the audit ledger publishes the
   * selected transition while full candidate evidence ships with the
   * Phase 4 vault.
   */
  recordTransitionEvaluation(stageVisitId: string, candidates: readonly unknown[]): void {
    this.requireBegun();
    this.transitionEvidence.push({ stageVisitId, candidates: [...candidates] });
  }

  /** Trusted domain annotations land in Phase 3; refuse loudly until then. */
  recordAnnotation(namespace: string, kind: string, _payload?: unknown, _anchorSequence?: number): void {
    this.requireBegun();
    throw new TraceError(
      `trace annotations (${namespace}/${kind}) arrive in Phase 3; ` +
        `the Phase 1 audit recorder cannot persist them`,
    );
  }

  /** Capture the terminal failure's stable taxonomy (no message). */
  recordRunError(exc: unknown): void {
    this.requireBegun();
    this.toolErrors.set("__run__", stableError(exc));
  }

  // -- live event observation ------------------------------------------

  /**
   * Project one live event into the redacted public ledger. Returns the
   * projected record, or null when the cleartext scanner forces record
   * omission (sequence gaps are valid and expected).
   */
  observeWorkflowEvent(event: WorkflowEvent): Record<string, unknown> | null {
    this.requireBegun();
    if (this.eventLimitExceeded || this.events.length >= LIMIT_EVENT_COUNT) {
      this.eventLimitExceeded = true;
      return null;
    }
    const record = this.project(event);
    if (record === null) return null;
    if (this.applyRegistry(record)) return null;
    if (this.scanAndMask(record)) return null;
    record.redacted_fields = [...new Set(record.redacted_fields as string[])].sort();
    if (this.events.length >= LIMIT_EVENT_COUNT) {
      this.eventLimitExceeded = true;
      return null;
    }
    this.events.push(record);
    return record;
  }

  // -- internals --------------------------------------------------------

  private requireBegun(): void {
    if (!this.begun) throw new TraceError("TraceRecorder used before beginRun");
    if (this.finished) throw new TraceError("TraceRecorder used after finishRun");
  }

  private newMarker(reason: RedactionReason, value: unknown, includeLength = true): Record<string, unknown> {
    this.redactionCount += 1;
    const inner: Record<string, unknown> = {
      token: `r-${this.redactionCount}`,
      reason,
      value_type: valueType(value),
    };
    if (includeLength) {
      if (typeof value === "string") {
        inner.length = textEncoder.encode(value).length;
      } else if (value instanceof Uint8Array || Array.isArray(value)) {
        inner.length = value.length;
      }
    }
    return { $redacted: inner };
  }

  private takeVisit(stageId: string): string {
    const queue = this.pendingVisits.get(stageId);
    let visit: string;
    if (queue && queue.length > 0) {
      visit = queue.shift() as string;
    } else {
      this.visitCount += 1;
      visit = `s-${this.visitCount}`;
    }
    this.currentVisit = visit;
    return visit;
  }

  private currentOrNewVisit(): string {
    if (this.currentVisit !== null) return this.currentVisit;
    this.visitCount += 1;
    this.currentVisit = `s-${this.visitCount}`;
    return this.currentVisit;
  }

  private peekModel(visit: string): string | null {
    const queue = this.pendingModels.get(visit);
    return queue && queue.length > 0 ? queue[queue.length - 1] : null;
  }

  private popModel(visit: string): string {
    const queue = this.pendingModels.get(visit);
    if (queue && queue.length > 0) return queue.shift() as string;
    this.modelCount += 1;
    return `m-${this.modelCount}`;
  }

  /** Consume the next begun-but-unstarted tool id for a started event. */
  private popTool(visit: string): string {
    const queue = this.pendingTools.get(visit);
    let callId: string;
    if (queue && queue.length > 0) {
      callId = queue.shift() as string;
    } else {
      this.toolCount += 1;
      callId = `t-${this.toolCount}`;
      if (!this.toolStartedAt.has(callId)) this.toolStartedAt.set(callId, this.config.clock());
    }
    const open = this.openTools.get(visit) ?? [];
    open.push(callId);
    this.openTools.set(visit, open);
    return callId;
  }

  /**
   * Resolve the tool id for a completed/failed event: the most recently
   * started call in the visit (nesting is strictly LIFO).
   */
  private peekTool(visit: string): string {
    const stack = this.openTools.get(visit);
    if (stack && stack.length > 0) return stack[stack.length - 1];
    const queue = this.pendingTools.get(visit);
    if (queue && queue.length > 0) return queue.shift() as string;
    this.toolCount += 1;
    const callId = `t-${this.toolCount}`;
    if (!this.toolStartedAt.has(callId)) this.toolStartedAt.set(callId, this.config.clock());
    return callId;
  }

  private base(
    event: WorkflowEvent,
    opts: { stageVisitId?: string } = {},
  ): Record<string, unknown> {
    const record: Record<string, unknown> = {
      kind: event.kind,
      run_id: this.config.traceId,
      timestamp: this.config.clock().toISOString(),
      redacted_fields: [] as string[],
    };
    if (Number.isInteger(event.sequence) && event.sequence >= 1) {
      record.sequence = event.sequence;
    }
    if (event.stageId !== undefined && event.stageId !== null) {
      record.stage_id = event.stageId;
    }
    if (opts.stageVisitId !== undefined) {
      record.stage_visit_id = opts.stageVisitId;
    }
    return record;
  }

  private project(event: WorkflowEvent): Record<string, unknown> | null {
    switch (event.kind) {
      case "run_started":
        return this.projectRunStarted(event);
      case "stage_started":
        return this.projectStageStarted(event);
      case "model_delta":
        return this.projectModelDelta(event);
      case "model_completed":
        return this.projectModelCompleted(event);
      case "model_retry":
        return this.projectModelRetry(event);
      case "tool_call_started":
        return this.projectToolStarted(event);
      case "tool_call_completed":
        return this.projectToolCompleted(event);
      case "tool_call_failed":
        return this.projectToolFailed(event);
      case "policy_checked":
        return this.projectPolicyChecked(event);
      case "policy_denied":
        return this.projectPolicyDenied(event);
      case "transition_selected":
        return this.projectTransitionSelected(event);
      case "stage_completed":
        return this.projectStageCompleted(event);
      case "run_completed":
        return this.projectRunCompleted(event);
      case "run_failed":
        return this.projectRunFailed(event);
      default:
        // Unknown future kinds: omit rather than guess.
        return null;
    }
  }

  private projectRunStarted(event: WorkflowEvent): Record<string, unknown> {
    const record = this.base(event);
    record.metadata = {
      workflow_id: this.manifest?.workflowId ?? "unknown",
      entry: this.manifest?.entryStageId ?? "unknown",
    };
    return record;
  }

  private projectStageStarted(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.takeVisit(event.stageId ?? "");
    return this.base(event, { stageVisitId: visit });
  }

  private projectModelDelta(event: WorkflowEvent): Record<string, unknown> {
    // Deltas belong to the enclosing visit; never consume the queued visit
    // id (later events in the same visit still need it).
    let visit = this.currentVisit;
    if (visit === null) {
      this.visitCount += 1;
      visit = `s-${this.visitCount}`;
      this.currentVisit = visit;
    }
    const record = this.base(event, { stageVisitId: visit });
    let callId = this.peekModel(visit);
    if (callId === null) {
      this.modelCount += 1;
      callId = `m-${this.modelCount}`;
      const queue = this.pendingModels.get(visit) ?? [];
      queue.push(callId);
      this.pendingModels.set(visit, queue);
    }
    record.model_call_id = callId;
    if (event.channel !== undefined && event.channel !== null) {
      record.channel = event.channel;
    }
    const text = typeof event.text === "string" ? event.text : "";
    if (event.channel === "reasoning") {
      record.text = this.newMarker("reasoning", text, false);
    } else {
      record.text = this.newMarker("private_content", text);
    }
    record.redacted_fields = ["/text"];
    return record;
  }

  private projectModelCompleted(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    const callId = this.popModel(visit);
    record.model_call_id = callId;
    const metadata: Record<string, unknown> = { content_omitted: true };
    const bytes = this.modelBytes.get(callId);
    if (bytes !== undefined) metadata.response_bytes = bytes;
    record.metadata = metadata;
    return record;
  }

  private projectModelRetry(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    const callId = this.peekModel(visit);
    if (callId !== null) record.model_call_id = callId;
    const metadata = (event.metadata ?? {}) as Record<string, unknown>;
    record.metadata = {
      attempt: safeInt(metadata.attempt, 1, 1),
      max_retries: safeInt(metaField(metadata, "maxRetries", "max_retries"), 0, 0),
      category: safeCategory(metadata.category),
    };
    record.error = "model_retry";
    return record;
  }

  private projectToolStarted(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    const callId = this.popTool(visit);
    record.tool_call_id = callId;
    const capability = event.capability ?? "unknown";
    record.capability = capability;
    const redacted = record.redacted_fields as string[];
    if (
      typeof event.toolName === "string" &&
      event.toolName.length <= MAX_TOOL_NAME_LEN &&
      /^[A-Za-z0-9][A-Za-z0-9._:\-]*$/.test(event.toolName)
    ) {
      record.tool_name = event.toolName;
    } else {
      redacted.push("/tool_name");
    }
    const args = (event.args ?? {}) as Record<string, unknown>;
    const [projected, pointers] = this.projectToolArgs(capability, args);
    if (Object.keys(projected).length > 0) record.args = projected;
    redacted.push(...pointers);
    return record;
  }

  private projectToolCompleted(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    const callId = this.peekTool(visit);
    record.tool_call_id = callId;
    record.capability = event.capability ?? "unknown";
    if (
      typeof event.toolName === "string" &&
      event.toolName.length <= MAX_TOOL_NAME_LEN &&
      /^[A-Za-z0-9][A-Za-z0-9._:\-]*$/.test(event.toolName)
    ) {
      record.tool_name = event.toolName;
    }
    const metadata: Record<string, unknown> = { result_status: "ok" };
    const resultType = this.toolResultTypes.get(callId);
    if (resultType !== undefined) metadata.result_type = resultType;
    const started = this.toolStartedAt.get(callId);
    if (started !== undefined) {
      metadata.duration_ms = Math.max(0, this.config.clock().getTime() - started.getTime());
    }
    record.metadata = metadata;
    return record;
  }

  private projectToolFailed(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    const callId = this.peekTool(visit);
    record.tool_call_id = callId;
    record.capability = event.capability ?? "unknown";
    if (
      typeof event.toolName === "string" &&
      event.toolName.length <= MAX_TOOL_NAME_LEN &&
      /^[A-Za-z0-9][A-Za-z0-9._:\-]*$/.test(event.toolName)
    ) {
      record.tool_name = event.toolName;
    }
    const stored = this.toolErrors.get(callId);
    // Kind-fixed code per redaction-policy §9; taxonomy in error_type.
    record.error = "tool_failed";
    record.metadata = { error_type: stored?.typeName ?? "ToolExecutionError" };
    return record;
  }

  private policyRef(policyId: unknown): string | null {
    if (typeof policyId !== "string") return null;
    return this.policyRefs.get(policyId) ?? null;
  }

  private projectPolicyChecked(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    record.capability = event.capability ?? "unknown";
    const metadata = (event.metadata ?? {}) as Record<string, unknown>;
    const kindValue = metaField(metadata, "policyKind", "policy_kind");
    const kind = kindValue === "before" || kindValue === "deny" ? kindValue : "deny";
    const out: Record<string, unknown> = { policy_kind: kind };
    const redacted = record.redacted_fields as string[];
    const ref = this.policyRef(metaField(metadata, "policyId", "policy_id"));
    if (ref === null) {
      redacted.push("/metadata/policy_id");
    } else {
      out.policy_ref = ref;
    }
    if (kind === "deny") {
      out.denied = Boolean(metadata.denied ?? false);
    } else {
      const required = metaField(metadata, "requiredCapabilities", "required_capabilities");
      if (Array.isArray(required) && required.every((c) => typeof c === "string")) {
        out.required_capabilities = [...new Set(required as string[])].sort();
      }
    }
    record.metadata = out;
    return record;
  }

  private projectPolicyDenied(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    record.capability = event.capability ?? "unknown";
    const metadata = (event.metadata ?? {}) as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const redacted = record.redacted_fields as string[];
    const ref = this.policyRef(metaField(metadata, "policyId", "policy_id"));
    if (ref === null) {
      redacted.push("/metadata/policy_id");
    } else {
      out.policy_ref = ref;
    }
    record.metadata = out;
    record.error = "policy_denied";
    return record;
  }

  private static readonly TRANSITION_REASONS = new Set([
    "explicit_transition",
    "backward_ref_loop",
    "next_stage_required_input_available",
    "skip_next_stage_required_input_missing",
    "fallthrough",
    "other",
  ]);

  private projectTransitionSelected(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    record.transition_to = event.transitionTo ?? "unknown";
    const metadata = (event.metadata ?? {}) as Record<string, unknown>;
    const reason =
      typeof metadata.reason === "string" && TraceRecorder.TRANSITION_REASONS.has(metadata.reason)
        ? metadata.reason
        : "other";
    record.metadata = {
      reason,
      priority: safeInt(metadata.priority, 0, 0),
    };
    return record;
  }

  private projectStageCompleted(event: WorkflowEvent): Record<string, unknown> {
    const visit = this.currentOrNewVisit();
    const record = this.base(event, { stageVisitId: visit });
    this.stageCompletedCount += 1;
    const output = (event.output ?? {}) as Record<string, unknown>;
    const [projected, pointers] = this.projectStageOutput(event.stageId ?? "", output);
    record.output = projected;
    record.redacted_fields = pointers;
    return record;
  }

  private projectRunCompleted(event: WorkflowEvent): Record<string, unknown> {
    const record = this.base(event);
    // Real runtime results carry { output, state }; anything else (including
    // the raw mappings a fixture may supply) is markered as a whole, exactly
    // like the Python recorder's getattr fallback.
    const result = event.result as { output?: unknown } | null | undefined;
    const output =
      result !== null && typeof result === "object" && "output" in result
        ? result.output
        : event.result;
    record.result = this.newMarker("private_content", output ?? null);
    record.metadata = { step_count: this.stageCompletedCount };
    record.redacted_fields = ["/result"];
    return record;
  }

  private projectRunFailed(event: WorkflowEvent): Record<string, unknown> {
    const record = this.base(event);
    const stored = this.toolErrors.get("__run__");
    this.toolErrors.delete("__run__");
    record.error = "run_failed";
    record.metadata = { error_type: stored?.typeName ?? "UnknownError" };
    return record;
  }

  // -- capability + output projection ----------------------------------

  private normalizePath(raw: unknown): { path?: string; pathRef?: string; rootClass?: string } {
    const text = String(raw ?? "");
    let candidate = text;
    // Longest registered root wins; roots are stored without trailing slash.
    const aliases = Object.entries(this.config.pathAliases).sort(
      ([, a], [, b]) => b.length - a.length,
    );
    for (const [alias, root] of aliases) {
      if (candidate !== root && !candidate.startsWith(`${root}/`)) continue;
      const relative = candidate === root ? "" : candidate.slice(root.length + 1);
      if (this.config.safePathAliases.has(alias)) {
        return { path: relative ? `${alias}/${relative}` : alias, rootClass: alias };
      }
      let ref = this.pathRefs.get(candidate);
      if (ref === undefined) {
        this.pathRefCount += 1;
        ref = `path-${this.pathRefCount}`;
        this.pathRefs.set(candidate, ref);
      }
      return { pathRef: ref, rootClass: alias };
    }
    let ref = this.pathRefs.get(text);
    if (ref === undefined) {
      this.pathRefCount += 1;
      ref = `path-${this.pathRefCount}`;
      this.pathRefs.set(text, ref);
    }
    return { pathRef: ref };
  }

  private projectToolArgs(
    capability: string,
    args: Record<string, unknown>,
  ): [Record<string, unknown>, string[]] {
    const redacted: string[] = [];
    if (capability === "fs.read") {
      return this.projectPathArgs(args, ["path"], redacted);
    }
    if (capability === "fs.write") {
      const [projected] = this.projectPathArgs(args, ["path"], redacted);
      if ("content" in args) {
        projected.content = this.newMarker("private_content", args.content);
        redacted.push("/args/content");
      }
      for (const key of Object.keys(args)) {
        if (key !== "path" && key !== "content") redacted.push(`/args/${key}`);
      }
      return [projected, redacted];
    }
    if (capability === "os.shell") {
      for (const key of Object.keys(args)) redacted.push(`/args/${key}`);
      return [{}, redacted];
    }
    if (capability === "http.fetch") {
      const projected: Record<string, unknown> = {};
      const method = args.method;
      if (typeof method === "string" && method.length <= MAX_METHOD_LEN && /^[A-Z]+$/.test(method)) {
        projected.method = method;
      } else if ("method" in args) {
        redacted.push("/args/method");
      }
      for (const key of ["url", "headers", "body"] as const) {
        if (key in args) {
          if (key !== "url") {
            projected[key] = this.newMarker("private_content", args[key]);
          }
          redacted.push(`/args/${key}`);
        }
      }
      for (const key of Object.keys(args)) {
        if (key !== "method" && key !== "url" && key !== "headers" && key !== "body") {
          redacted.push(`/args/${key}`);
        }
      }
      return [projected, redacted];
    }
    if (
      capability === "user.elicit" ||
      capability === "user.confirm" ||
      capability === "browser.storage.read" ||
      capability === "browser.storage.write" ||
      capability === "browser.js.run" ||
      capability === "browser.js.sandbox"
    ) {
      const projected: Record<string, unknown> = {};
      for (const key of Object.keys(args)) {
        projected[key] = this.newMarker("private_content", args[key]);
        redacted.push(`/args/${key}`);
      }
      return [projected, redacted];
    }
    // Unknown capability: name/status/timing only; all args private.
    if (Object.keys(args).length > 0) redacted.push("/args");
    return [{}, redacted];
  }

  private projectPathArgs(
    args: Record<string, unknown>,
    allowKeys: readonly string[],
    redacted: string[],
  ): [Record<string, unknown>, string[]] {
    const projected: Record<string, unknown> = {};
    for (const key of allowKeys) {
      if (!(key in args)) continue;
      const { path, pathRef, rootClass } = this.normalizePath(args[key]);
      if (path !== undefined) {
        projected.path = path;
        if (rootClass !== undefined) projected.root_class = rootClass;
      } else if (pathRef !== undefined) {
        projected.path_ref = pathRef;
        if (rootClass !== undefined) projected.root_class = rootClass;
      } else {
        redacted.push(`/args/${key}`);
      }
    }
    for (const key of Object.keys(args)) {
      if (!allowKeys.includes(key)) redacted.push(`/args/${key}`);
    }
    return [projected, redacted];
  }

  private projectStageOutput(
    stageId: string,
    output: Record<string, unknown>,
  ): [Record<string, unknown>, string[]] {
    const projected: Record<string, unknown> = {};
    const redacted: string[] = [];
    const writes = this.stageWrites(stageId);
    for (const name of Object.keys(output)) {
      if (writes !== null && !writes.has(name)) {
        projected[name] = this.newMarker("unapproved_field", output[name]);
        redacted.push(`/output/${name}`);
        continue;
      }
      const value = output[name];
      if (this.config.approvedMetrics.has(`${stageId}.${name}`) && isMetricValue(value)) {
        projected[name] = value;
        continue;
      }
      projected[name] = this.newMarker(value instanceof Uint8Array ? "private_content" : outputReason(value), value);
      redacted.push(`/output/${name}`);
    }
    return [projected, redacted];
  }

  private stageWrites(stageId: string): Set<string> | null {
    if (this.manifest === null) return null;
    for (const stage of this.manifest.stages) {
      if (stage.id === stageId) {
        return new Set(stage.writes.map((w) => w.name));
      }
    }
    return null;
  }

  // -- secret registry + scanner application ---------------------------

  private applyRegistry(record: Record<string, unknown>): boolean {
    for (let pass = 0; pass < MAX_MASK_PASSES; pass += 1) {
      const hits = scanStrings(record, "", this.registry).filter((f) => f.rule === "registered_secret");
      if (hits.length === 0) return false;
      const pointer = hits[0].pointer;
      if (isMaskable(pointer)) {
        this.setMarker(record, pointer, "credential");
      } else {
        // Structural field echoed a credential: omit the record.
        return true;
      }
    }
    return true;
  }

  private setMarker(record: Record<string, unknown>, pointer: string, reason: RedactionReason): void {
    const parts = pointer.split("/").slice(1).map(unescapePointerSegment);
    let current: unknown = record;
    for (const part of parts.slice(0, -1)) {
      if (current !== null && typeof current === "object" && part in (current as Record<string, unknown>)) {
        current = (current as Record<string, unknown>)[part];
      } else {
        return;
      }
    }
    const last = parts[parts.length - 1];
    if (current !== null && typeof current === "object" && last in (current as Record<string, unknown>)) {
      (current as Record<string, unknown>)[last] = this.newMarker(reason, (current as Record<string, unknown>)[last]);
      const fields = record.redacted_fields as string[];
      if (!fields.includes(pointer)) fields.push(pointer);
    }
  }

  private scanAndMask(record: Record<string, unknown>): boolean {
    for (let pass = 0; pass < MAX_MASK_PASSES; pass += 1) {
      const findings = scanStrings(record, "", this.registry).filter((f) => f.rule !== "registered_secret");
      if (findings.length === 0) return false;
      const finding = findings[0];
      if (!isMaskable(finding.pointer)) return true;
      const reason: RedactionReason =
        finding.rule === "home_path"
          ? "absolute_path"
          : CREDENTIAL_RULES.has(finding.rule)
            ? "credential"
            : "unapproved_field";
      this.setMarker(record, finding.pointer, reason);
    }
    return true;
  }

  // -- archive assembly --------------------------------------------------

  private async buildEntries(status: TraceStatus): Promise<Record<string, Uint8Array>> {
    const manifest = this.manifest;
    const workflowId = manifest?.workflowId ?? "unknown";
    const prov = this.config.provenance;
    const complete = prov.irSha256 !== null;
    const provenance: Record<string, unknown> = {
      complete,
      frontend: prov.frontend,
      target: ["python", "web", "manual", "imported"].includes(prov.target) ? prov.target : "manual",
      compilerVersion: prov.compilerVersion,
      runtime: { name: RUNTIME_NAME, version: RUNTIME_VERSION },
    };
    if (this.config.model !== undefined) {
      const model: Record<string, unknown> = { name: this.config.model.name };
      if (this.config.model.apiMode !== undefined) model.api_mode = this.config.model.apiMode;
      const sampling: Record<string, unknown> = {};
      if (this.config.model.temperature !== undefined) sampling.temperature = this.config.model.temperature;
      if (this.config.model.maxTokens !== undefined) sampling.max_tokens = this.config.model.maxTokens;
      if (Object.keys(sampling).length > 0) model.sampling = sampling;
      provenance.model = model;
    }
    const exits = manifest ? [...manifest.exitStageIds].sort() : [];
    const manifestObj: Record<string, unknown> = {
      format: TRACE_FORMAT,
      trace_id: this.config.traceId,
      created_at: (this.beginTime ?? this.config.clock()).toISOString(),
      status,
      capture: {
        profile: "audit",
        vault_present: false,
        publication_eligible: false,
        redaction_policy: REDACTION_POLICY,
        scanner: { status: "passed", ruleset: SCANNER_RULESET },
      },
      workflow: {
        id: workflowId,
        ir_version: prov.irVersion,
        ir_sha256: prov.irSha256,
        entry: manifest?.entryStageId ?? "unknown",
        exits,
      },
      provenance,
      integrity: { algorithm: "sha256", entry: INTEGRITY_PATH },
      viewer: { min_format: TRACE_FORMAT },
    };
    const graphObj = this.buildGraph();
    const eventsText = this.events.map((e) => `${canonicalStringify(e)}\n`).join("");
    const eventsBytes = textEncoder.encode(eventsText);
    const eventsSha = await sha256Hex(eventsBytes);
    const kinds: Record<string, number> = {};
    const visits = new Set<string>();
    for (const event of this.events) {
      const kind = typeof event.kind === "string" ? event.kind : "?";
      kinds[kind] = (kinds[kind] ?? 0) + 1;
      if (typeof event.stage_visit_id === "string") visits.add(event.stage_visit_id);
    }
    const finishTime = this.config.clock();
    const beginTime = this.beginTime ?? finishTime;
    const summaryObj: Record<string, unknown> = {
      format: SUMMARY_FORMAT,
      events_sha256: eventsSha,
      event_count: this.events.length,
      stage_visit_count: visits.size,
      duration_ms: Math.max(0, finishTime.getTime() - beginTime.getTime()),
      counts_by_kind: kinds,
    };
    const payloads: Record<string, Uint8Array> = {
      [MANIFEST_PATH]: textEncoder.encode(canonicalStringify(manifestObj)),
      [GRAPH_PATH]: textEncoder.encode(canonicalStringify(graphObj)),
      [EVENTS_PATH]: eventsBytes,
      [SUMMARY_PATH]: textEncoder.encode(canonicalStringify(summaryObj)),
    };
    const integrityEntries = await Promise.all(
      Object.entries(payloads)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(async ([path, data]) => ({
          path,
          media_type: path.endsWith(".ndjson") ? "application/x-ndjson" : "application/json",
          uncompressed_bytes: data.length,
          sha256: await sha256Hex(data),
        })),
    );
    const identityObj = {
      format: CONTENT_IDENTITY_FORMAT,
      entries: [...integrityEntries]
        .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
        .map((e) => ({ path: e.path, sha256: e.sha256, uncompressed_bytes: e.uncompressed_bytes })),
    };
    const integrityObj: Record<string, unknown> = {
      format: "nemoir.trace.integrity/0.1",
      algorithm: "sha256",
      entries: integrityEntries,
      content_identity: await sha256Hex(textEncoder.encode(canonicalStringify(identityObj))),
    };
    payloads[INTEGRITY_PATH] = textEncoder.encode(canonicalStringify(integrityObj));
    return payloads;
  }

  private buildGraph(): Record<string, unknown> {
    const manifest = this.manifest;
    const nodes = (manifest?.stages ?? []).map((stage) => ({
      id: stage.id,
      execution: stage.execution.kind === "tool" ? "tool" : "model",
      capabilities: [...stage.requires].sort(),
      writes: stage.writes.map((w) => ({ name: w.name, type: w.type, optional: w.optional })),
    }));
    const transitions = (manifest?.stages ?? []).flatMap((stage) =>
      stage.transitions.map((t) => {
        const kinds = ["always", "has_value", "missing", "eq", "if"];
        return {
          from: stage.id,
          to: t.to,
          priority: Math.max(0, Math.trunc(t.priority) || 0),
          guard_kind: kinds.includes(t.guard.kind) ? t.guard.kind : "always",
        };
      }),
    );
    const policies = (manifest?.policies ?? []).map((policy, index) => {
      const entry: Record<string, unknown> = {
        ref: `p-${index + 1}`,
        kind: policy.kind === "before" ? "before" : "deny",
        trigger_capability: policy.trigger.capability,
      };
      if (entry.kind === "before") {
        entry.required_capabilities = [...new Set(policy.requires.map((r) => r.capability))].sort();
      }
      return entry;
    });
    return {
      format: GRAPH_FORMAT,
      workflow_id: manifest?.workflowId ?? "unknown",
      entry: manifest?.entryStageId ?? "unknown",
      exits: manifest ? [...manifest.exitStageIds].sort() : [],
      nodes,
      transitions,
      policies,
    };
  }

  private finalScan(entries: Record<string, Uint8Array>): void {
    const problems: string[] = [];
    for (const [path, data] of Object.entries(entries)) {
      if (path.endsWith(".ndjson")) {
        const lines = textDecoder.decode(data).split("\n");
        lines.forEach((line, index) => {
          if (line.trim() === "") return;
          let value: unknown;
          try {
            value = parseJsonStrict(line);
          } catch (error) {
            problems.push(`${path}:${index + 1}: unparsable (${String(error)})`);
            return;
          }
          for (const finding of scanStrings(value, "", this.registry)) {
            problems.push(`${path}:${index + 1}:${finding.pointer} [${finding.rule}]`);
          }
          if (hasUnsafeInt(value)) {
            problems.push(`${path}:${index + 1} [unsafe_integer]`);
          }
        });
      } else {
        let value: unknown;
        try {
          value = parseJsonStrict(textDecoder.decode(data));
        } catch (error) {
          problems.push(`${path}: unparsable (${String(error)})`);
          continue;
        }
        for (const finding of scanStrings(value, "", this.registry)) {
          problems.push(`${path}:${finding.pointer} [${finding.rule}]`);
        }
        if (hasUnsafeInt(value)) {
          problems.push(`${path} [unsafe_integer]`);
        }
      }
      if (scanStrings({ name: path }, "/name", this.registry).length > 0) {
        problems.push(`${path}: filename finding`);
      }
    }
    if (problems.length > 0) {
      const detail = problems.slice(0, 10).join("; ");
      throw new TraceError(
        `trace scanner blocked finalization with ${problems.length} finding(s): ${detail}`,
      );
    }
  }
}

export class NoOpTraceRecorder {
  /** Zero-cost recorder used when tracing is disabled. */
  beginRun(_manifest: WorkflowManifest): void {}
  async finishRun(_status: TraceStatus): Promise<Uint8Array> {
    return new Uint8Array(0);
  }
  beginStageVisit(_stageId: string): string {
    return "";
  }
  beginModelCall(_stageId = "", _stageVisitId?: string): string {
    return "";
  }
  recordModelResponse(_modelCallId: string, _facts: { responseBytes?: number; toolCallCount?: number } = {}): void {}
  beginToolCall(_stageId = "", _stageVisitId?: string): string {
    return "";
  }
  recordToolResult(_toolCallId: string, _result: unknown): void {}
  recordToolError(_toolCallId: string, _exc: unknown): void {}
  recordRunError(_exc: unknown): void {}
  recordTransitionEvaluation(_stageVisitId: string, _candidates: readonly unknown[]): void {}
  recordAnnotation(_namespace: string, _kind: string, _payload?: unknown, _anchorSequence?: number): void {}
  observeWorkflowEvent(_event: WorkflowEvent): null {
    return null;
  }
}

export const NO_OP = new NoOpTraceRecorder();

export function resolveRecorder(
  value: TraceRecorder | NoOpTraceRecorder | null | undefined,
): TraceRecorder | NoOpTraceRecorder {
  return value ?? NO_OP;
}

/**
 * Resolve a host trace value to a fresh per-run recorder (or null).
 * Mirrors `resolve_trace_recorder` in Python: `TraceConfig` values adopt
 * `defaultProvenance`/`defaultModel` for fields the host left unspecified.
 */
export function resolveTraceRecorder(
  value: TraceValue,
  opts: { defaultProvenance?: HostProvenance; defaultModel?: ModelDescriptor } = {},
): TraceRecorder | null {
  if (value === null || value === undefined) return null;
  if (value instanceof TraceRecorder) return value;
  if (value instanceof NoOpTraceRecorder) return null;
  if (typeof value === "function") {
    const recorder = value();
    if (recorder !== null && !(recorder instanceof TraceRecorder)) {
      throw new TraceError(
        `trace factory must return TraceRecorder or null, got ${typeof recorder}`,
      );
    }
    return recorder;
  }
  if (typeof value === "object") {
    const config = value as TraceConfig;
    let provenance = config.provenance ?? incompleteProvenance();
    if (
      provenance.irSha256 === null &&
      opts.defaultProvenance !== undefined &&
      opts.defaultProvenance.irSha256 !== null
    ) {
      provenance = opts.defaultProvenance;
    }
    const model = config.model ?? opts.defaultModel;
    return new TraceRecorder({ ...config, provenance, model });
  }
  throw new TraceError(`unsupported trace value: ${typeof value}`);
}

// ---------------------------------------------------------------------------
// Archive writing + reading + verification
// ---------------------------------------------------------------------------

/** Deterministic ZIP assembly: sorted names, fixed epoch, DEFLATE level 6. */
export function writeArchive(entries: Record<string, Uint8Array>): Uint8Array {
  const sorted: Record<string, Uint8Array> = {};
  for (const name of Object.keys(entries).sort()) {
    sorted[name] = entries[name];
  }
  return zipSync(sorted, { level: ZIP_DEFLATE_LEVEL, mtime: ZIP_EPOCH });
}

interface ZipEntryMeta {
  readonly name: string;
  readonly method: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
}

/** Parse the ZIP central directory without inflating (bomb-safe budgets). */
function parseCentralDirectory(data: Uint8Array): ZipEntryMeta[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // Locate EOCD: signature 0x06054b50 within the last 64KB + 22 bytes.
  const scanStart = Math.max(0, data.length - 65557);
  let eocd = -1;
  for (let i = data.length - 22; i >= scanStart; i -= 1) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new TraceError("not a valid trace archive: EOCD missing");
  const entryCount = view.getUint16(eocd + 10, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  const commentLen = view.getUint16(eocd + 20, true);
  if (view.getUint16(eocd + 4, true) !== 0 || view.getUint16(eocd + 6, true) !== 0) {
    throw new TraceError("trace archive must be single-disk");
  }
  if (commentLen !== 0) throw new TraceError("trace archive must not carry a comment");
  const entries: ZipEntryMeta[] = [];
  let cursor = cdOffset;
  for (let n = 0; n < entryCount; n += 1) {
    if (view.getUint32(cursor, true) !== 0x02014b50) {
      throw new TraceError("not a valid trace archive: central directory corrupt");
    }
    const flags = view.getUint16(cursor + 8, true);
    const method = view.getUint16(cursor + 10, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const uncompressedSize = view.getUint32(cursor + 24, true);
    const nameLen = view.getUint16(cursor + 28, true);
    const extraLen = view.getUint16(cursor + 30, true);
    const commentLenEntry = view.getUint16(cursor + 32, true);
    if (flags & 0x1) throw new TraceError("trace archive must not contain encrypted entries");
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff) {
      throw new TraceError("trace archive must not use ZIP64");
    }
    const nameBytes = data.subarray(cursor + 46, cursor + 46 + nameLen);
    const name = textDecoder.decode(nameBytes);
    entries.push({ name, method, compressedSize, uncompressedSize });
    cursor += 46 + nameLen + extraLen + commentLenEntry;
  }
  return entries;
}

/**
 * Read and structurally validate a `.nemotrace` container. Enforces the
 * entry allowlist and size/ratio budgets before trusting payload bytes.
 */
export function readArchiveEntries(data: Uint8Array): Record<string, Uint8Array> {
  if (data.length > LIMIT_COMPRESSED_BYTES) {
    throw new TraceError(`trace archive exceeds ${LIMIT_COMPRESSED_BYTES} compressed bytes`);
  }
  let metas: ZipEntryMeta[];
  try {
    metas = parseCentralDirectory(data);
  } catch (error) {
    if (error instanceof TraceError) throw error;
    throw new TraceError(`not a valid trace archive: ${String(error)}`);
  }
  const names = metas.map((m) => m.name);
  const sorted = [...names].sort();
  if (names.some((n, i) => n !== sorted[i]) || new Set(names).size !== names.length) {
    throw new TraceError("trace archive entries must be sorted and unique");
  }
  const allowed = new Set([...AUDIT_ENTRY_PATHS, INTEGRITY_PATH]);
  for (const name of names) {
    if (!allowed.has(name)) throw new TraceError(`trace archive has unexpected entry: ${name}`);
    if (name.includes("\\") || name.startsWith("/") || name.split("/").some((s) => s === "" || s === "." || s === "..")) {
      throw new TraceError(`trace archive has unsafe entry name: ${name}`);
    }
  }
  let total = 0;
  for (const meta of metas) {
    if (meta.method !== 8) {
      throw new TraceError(`trace archive entry ${meta.name} must use DEFLATE`);
    }
    if (meta.uncompressedSize > LIMIT_UNCOMPRESSED_ENTRY_BYTES) {
      throw new TraceError(`trace entry ${meta.name} exceeds size budget`);
    }
    if (meta.compressedSize > 0 && meta.uncompressedSize / Math.max(meta.compressedSize, 1) > LIMIT_COMPRESSION_RATIO) {
      throw new TraceError(`trace entry ${meta.name} exceeds compression-ratio budget`);
    }
    total += meta.uncompressedSize;
    if (total > LIMIT_UNCOMPRESSED_TOTAL_BYTES) {
      throw new TraceError("trace archive exceeds uncompressed budget");
    }
  }
  let inflated: Record<string, Uint8Array>;
  try {
    inflated = unzipSync(data) as Record<string, Uint8Array>;
  } catch (error) {
    throw new TraceError(`not a valid trace archive: ${String(error)}`);
  }
  // Directory entries (trailing slash) are rejected by the name check above,
  // but confirm no name vanished or appeared during inflation.
  const inflatedNames = Object.keys(inflated).sort();
  if (inflatedNames.length !== names.length || inflatedNames.some((n, i) => n !== sorted[i])) {
    throw new TraceError("trace archive inflation mismatch");
  }
  return inflated;
}

/** Verify hashes, content identity, and summary consistency. */
export async function verifyArchive(data: Uint8Array): Promise<VerificationReport> {
  let entries: Record<string, Uint8Array>;
  try {
    entries = readArchiveEntries(data);
  } catch (error) {
    return { ok: false, contentIdentity: null, warnings: [], errors: [String(error)] };
  }
  const errors: string[] = [];
  const warnings: string[] = [];
  for (const required of [MANIFEST_PATH, GRAPH_PATH, EVENTS_PATH, INTEGRITY_PATH]) {
    if (!(required in entries)) errors.push(`missing required entry ${required}`);
  }
  if (errors.length > 0) return { ok: false, contentIdentity: null, warnings, errors };
  let integrity: Record<string, unknown>;
  try {
    integrity = parseJsonStrict(textDecoder.decode(entries[INTEGRITY_PATH])) as Record<string, unknown>;
  } catch (error) {
    return { ok: false, contentIdentity: null, warnings: [], errors: [`integrity.json unparsable: ${String(error)}`] };
  }
  const indexed = new Map<string, { sha256: unknown; uncompressed_bytes: unknown }>();
  if (Array.isArray(integrity.entries)) {
    for (let idx = 0; idx < (integrity.entries as unknown[]).length; idx += 1) {
      const item = (integrity.entries as unknown[])[idx];
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        errors.push(`integrity.json: entry ${idx} must be an object`);
        continue;
      }
      const record = item as Record<string, unknown>;
      const p = record.path;
      const s = record.sha256;
      const ub = record.uncompressed_bytes;
      if (typeof p !== "string") {
        errors.push(`integrity.json: entry ${idx} missing or invalid path`);
        continue;
      }
      if (typeof s !== "string" || !/^sha256:[0-9a-f]{64}$/.test(s as string)) {
        errors.push(`integrity.json: entry ${idx} invalid sha256`);
        continue;
      }
      if (typeof ub !== "number" || !Number.isInteger(ub as number) || (ub as number) < 0) {
        errors.push(`integrity.json: entry ${idx} invalid uncompressed_bytes`);
        continue;
      }
      if (indexed.has(p as string)) {
        errors.push(`integrity.json: duplicate path ${JSON.stringify(p)}`);
        continue;
      }
      indexed.set(p as string, { sha256: s, uncompressed_bytes: ub });
    }
  } else {
    errors.push("integrity.json: entries must be an array");
  }
  for (const [name, bytes] of Object.entries(entries)) {
    if (name === INTEGRITY_PATH) continue;
    const entry = indexed.get(name);
    if (entry === undefined) {
      errors.push(`${name} missing from integrity index`);
      continue;
    }
    if (entry.sha256 !== (await sha256Hex(bytes))) errors.push(`${name} hash mismatch`);
    if (entry.uncompressed_bytes !== bytes.length) errors.push(`${name} length mismatch`);
  }
  // Build identity only from valid indexed entries to avoid undefined sha.
  const identityEntries: Array<{ path: string; sha256: unknown; uncompressed_bytes: unknown }> = [];
  for (const [path, e] of indexed.entries()) {
    if (typeof e.sha256 === "string" && typeof e.uncompressed_bytes === "number") {
      identityEntries.push({ path, sha256: e.sha256, uncompressed_bytes: e.uncompressed_bytes });
    }
  }
  const identityObj = {
    format: CONTENT_IDENTITY_FORMAT,
    entries: identityEntries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
  };
  let recomputed = "";
  try {
    recomputed = await sha256Hex(textEncoder.encode(canonicalStringify(identityObj)));
  } catch (error) {
    return { ok: false, contentIdentity: null, warnings, errors: [...errors, `content identity failed: ${String(error)}`] };
  }
  const contentIdentity = integrity.content_identity;
  if (recomputed !== contentIdentity) errors.push("content identity mismatch");
  // Event count budget (hard failure).
  let eventLines: string[] = [];
  try {
    eventLines = textDecoder.decode(entries[EVENTS_PATH]).split("\n").filter((l) => l.trim() !== "");
    if (eventLines.length > LIMIT_EVENT_COUNT) {
      errors.push(`event count ${eventLines.length} exceeds budget ${LIMIT_EVENT_COUNT}`);
    }
  } catch (error) {
    errors.push(`event count check failed: ${String(error)}`);
    eventLines = [];
  }
  if (SUMMARY_PATH in entries) {
    try {
      const summary = parseJsonStrict(textDecoder.decode(entries[SUMMARY_PATH])) as Record<string, unknown>;
      const kinds: Record<string, number> = {};
      const visits = new Set<string>();
      for (const line of eventLines) {
        const event = parseJsonStrict(line) as Record<string, unknown>;
        const kind = typeof event.kind === "string" ? event.kind : "?";
        kinds[kind] = (kinds[kind] ?? 0) + 1;
        if (typeof event.stage_visit_id === "string") visits.add(event.stage_visit_id);
      }
      if (summary.event_count !== eventLines.length) warnings.push("summary event_count mismatch (recomputed)");
      if (JSON.stringify(summary.counts_by_kind) !== JSON.stringify(kinds)) {
        warnings.push("summary counts_by_kind mismatch (recomputed)");
      }
      if (summary.stage_visit_count !== visits.size) {
        warnings.push("summary stage_visit_count mismatch (recomputed)");
      }
      if (summary.events_sha256 !== (await sha256Hex(entries[EVENTS_PATH]))) {
        warnings.push("summary events_sha256 mismatch (recomputed)");
      }
    } catch (error) {
      warnings.push(`summary check skipped: ${String(error)}`);
    }
  }
  // Manifest validation (strict writer schema).
  let manifest: Record<string, unknown> | null = null;
  try {
    manifest = parseJsonStrict(textDecoder.decode(entries[MANIFEST_PATH])) as Record<string, unknown>;
    if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
      errors.push("manifest must be an object");
    } else {
      const requiredManifest = new Set([
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
      for (const field of requiredManifest) {
        if (!(field in manifest)) errors.push(`manifest missing required field '${field}'`);
      }
      const extra = Object.keys(manifest).filter((k) => !requiredManifest.has(k));
      if (extra.length > 0) warnings.push(`manifest has unexpected fields ${JSON.stringify(extra)} (ignored)`);
      if (manifest.format !== TRACE_FORMAT) errors.push("manifest format mismatch");
      if (typeof manifest.trace_id !== "string" || !/^[0-9a-f]{32}$/.test(manifest.trace_id as string)) {
        errors.push("manifest trace_id invalid");
      }
      if (!["complete", "failed", "interrupted"].includes(manifest.status as string)) {
        errors.push("manifest status invalid");
      }
      const cap = manifest.capture as Record<string, unknown> | undefined;
      if (cap === null || typeof cap !== "object" || Array.isArray(cap)) {
        errors.push("manifest capture invalid");
      }
      const wf = manifest.workflow as Record<string, unknown> | undefined;
      if (wf === null || typeof wf !== "object" || Array.isArray(wf)) {
        errors.push("manifest workflow invalid");
      } else {
        for (const wf_f of ["id", "ir_version", "ir_sha256", "entry", "exits"]) {
          if (!(wf_f in wf)) errors.push(`manifest workflow missing '${wf_f}'`);
        }
      }
    }
  } catch (error) {
    errors.push(`manifest unparsable: ${String(error)}`);
    manifest = null;
  }
  // Workflow graph validation (strict writer schema).
  let graph: unknown = null;
  try {
    graph = parseJsonStrict(textDecoder.decode(entries[GRAPH_PATH])) as unknown;
    if (graph === null || typeof graph !== "object" || Array.isArray(graph)) {
      errors.push("workflow graph must be an object");
    } else {
      const g = graph as Record<string, unknown>;
      for (const req of ["format", "workflow_id", "entry", "exits", "nodes", "transitions", "policies"]) {
        if (!(req in g)) errors.push(`workflow graph missing required field '${req}'`);
      }
      if (g.format !== "nemoir.trace.workflow-graph/0.1") errors.push("workflow graph format mismatch");
      if ("nodes" in g && !Array.isArray(g.nodes)) errors.push("workflow graph nodes must be an array");
      if (hasUnsafeInt(graph)) errors.push("workflow graph contains unsafe integer");
    }
  } catch (error) {
    errors.push(`workflow graph unparsable: ${String(error)}`);
  }
  if (manifest !== null && hasUnsafeInt(manifest)) {
    errors.push("manifest contains unsafe integer");
  }
  if (SUMMARY_PATH in entries) {
    try {
      const summaryObj = parseJsonStrict(textDecoder.decode(entries[SUMMARY_PATH])) as unknown;
      if (hasUnsafeInt(summaryObj)) errors.push("summary contains unsafe integer");
    } catch {
      // summary parse already warned above; ignore here
    }
  }
  if (hasUnsafeInt(integrity)) errors.push("integrity contains unsafe integer");
  // Integrity exact membership.
  {
    const expectedPayloads = new Set(Object.keys(entries).filter((k) => k !== INTEGRITY_PATH));
    const indexedKeys = new Set(indexed.keys());
    const missing = [...expectedPayloads].filter((k) => !indexedKeys.has(k));
    const extraIdx = [...indexedKeys].filter((k) => !expectedPayloads.has(k));
    if (missing.length > 0) errors.push(`integrity index missing entries: ${JSON.stringify(missing)}`);
    if (extraIdx.length > 0) errors.push(`integrity index has extra entries: ${JSON.stringify(extraIdx)}`);
  }
  // Per-event ledger validation (strict writer schema).
  try {
    const traceId = manifest !== null ? (manifest.trace_id as string | undefined) : undefined;
    const allowedKinds = new Set([
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
    const allowedKeys = new Set([
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
    for (let idx = 0; idx < eventLines.length; idx += 1) {
      const line = eventLines[idx];
      let ev: Record<string, unknown>;
      try {
        ev = parseJsonStrict(line) as Record<string, unknown>;
      } catch (error) {
        errors.push(`public/events.ndjson:${idx + 1} unparsable: ${String(error)}`);
        continue;
      }
      if (ev === null || typeof ev !== "object" || Array.isArray(ev)) {
        errors.push(`public/events.ndjson:${idx + 1} must be an object`);
        continue;
      }
      const kind = ev.kind as string | undefined;
      if (typeof kind !== "string" || !allowedKinds.has(kind)) {
        errors.push(`public/events.ndjson:${idx + 1} invalid kind ${JSON.stringify(kind)}`);
        continue;
      }
      const extraEv = Object.keys(ev).filter((k) => !allowedKeys.has(k));
      if (extraEv.length > 0) warnings.push(`public/events.ndjson:${idx + 1} has unexpected fields ${JSON.stringify(extraEv)} (ignored)`);
      const rid = ev.run_id as unknown;
      if (typeof rid !== "string" || !/^[0-9a-f]{32}$/.test(rid)) {
        errors.push(`public/events.ndjson:${idx + 1} invalid run_id`);
      } else if (traceId && rid !== traceId) {
        errors.push(`public/events.ndjson:${idx + 1} run_id mismatch`);
      }
      const ts = ev.timestamp as unknown;
      if (typeof ts !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(ts)) {
        errors.push(`public/events.ndjson:${idx + 1} invalid timestamp`);
      }
      const rf = ev.redacted_fields as unknown;
      if (!Array.isArray(rf) || JSON.stringify(rf) !== JSON.stringify([...new Set(rf as string[])].sort())) {
        errors.push(`public/events.ndjson:${idx + 1} invalid redacted_fields`);
      }
      if (kind === "annotation") {
        if ("sequence" in ev) errors.push(`public/events.ndjson:${idx + 1} annotation must not have sequence`);
        if (!("annotation" in ev)) errors.push(`public/events.ndjson:${idx + 1} annotation missing`);
      } else {
        if (!("sequence" in ev) || typeof ev.sequence !== "number" || !Number.isInteger(ev.sequence) || (ev.sequence as number) < 1) {
          errors.push(`public/events.ndjson:${idx + 1} missing or invalid sequence`);
        }
      }
      if (["stage_started", "model_delta", "model_completed", "model_retry", "tool_call_started", "tool_call_completed", "tool_call_failed", "policy_checked", "policy_denied", "transition_selected", "stage_completed"].includes(kind)) {
        if (!("stage_id" in ev) || !("stage_visit_id" in ev)) {
          errors.push(`public/events.ndjson:${idx + 1} missing stage_id/stage_visit_id`);
        } else {
          if (typeof ev.stage_id !== "string" || (ev.stage_id as string).length < 1 || (ev.stage_id as string).length > 256) {
            errors.push(`public/events.ndjson:${idx + 1} invalid stage_id`);
          }
          if (typeof ev.stage_visit_id !== "string" || !/^s-[1-9][0-9]*$/.test(ev.stage_visit_id as string)) {
            errors.push(`public/events.ndjson:${idx + 1} invalid stage_visit_id`);
          }
        }
      } else if ("stage_id" in ev) {
        if (typeof ev.stage_id !== "string" || (ev.stage_id as string).length < 1 || (ev.stage_id as string).length > 256) {
          errors.push(`public/events.ndjson:${idx + 1} invalid stage_id`);
        }
      }
      if ("stage_visit_id" in ev && !(["stage_started", "model_delta", "model_completed", "model_retry", "tool_call_started", "tool_call_completed", "tool_call_failed", "policy_checked", "policy_denied", "transition_selected", "stage_completed"].includes(kind))) {
        if (typeof ev.stage_visit_id !== "string" || !/^s-[1-9][0-9]*$/.test(ev.stage_visit_id as string)) {
          errors.push(`public/events.ndjson:${idx + 1} invalid stage_visit_id`);
        }
      }
      if (["model_delta", "model_completed", "model_retry"].includes(kind)) {
        if (typeof ev.model_call_id !== "string" || !/^m-[1-9][0-9]*$/.test(ev.model_call_id as string)) {
          errors.push(`public/events.ndjson:${idx + 1} invalid model_call_id`);
        }
      }
      if (["tool_call_started", "tool_call_completed", "tool_call_failed"].includes(kind)) {
        if (typeof ev.tool_call_id !== "string" || !/^t-[1-9][0-9]*$/.test(ev.tool_call_id as string)) {
          errors.push(`public/events.ndjson:${idx + 1} invalid tool_call_id`);
        }
      }
      // Optional field type/bound checks (per public-event.schema.json)
      if ("channel" in ev) {
        const ch = ev.channel as unknown;
        if (ch !== null && ch !== "assistant" && ch !== "progress" && ch !== "reasoning" && ch !== "reasoning_summary" && ch !== "debug") {
          errors.push(`public/events.ndjson:${idx + 1} invalid channel`);
        }
      }
      if ("tool_name" in ev) {
        const tn = ev.tool_name as unknown;
        if (typeof tn !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:\-]*$/.test(tn as string) || (tn as string).length > 128) {
          errors.push(`public/events.ndjson:${idx + 1} invalid tool_name`);
        }
      }
      if ("capability" in ev) {
        const cap = ev.capability as unknown;
        if (typeof cap !== "string" || (cap as string).length < 1 || (cap as string).length > 128) {
          errors.push(`public/events.ndjson:${idx + 1} invalid capability`);
        }
      }
      if ("error" in ev) {
        const err = ev.error as unknown;
        if (typeof err !== "string" || !/^[a-z][a-z0-9_]*$/.test(err as string) || (err as string).length > 64) {
          errors.push(`public/events.ndjson:${idx + 1} invalid error`);
        }
      }
      if ("transition_to" in ev) {
        const tr = ev.transition_to as unknown;
        if (typeof tr !== "string" || (tr as string).length < 1 || (tr as string).length > 256) {
          errors.push(`public/events.ndjson:${idx + 1} invalid transition_to`);
        }
      }
      if ("anchor_sequence" in ev) {
        const anc = ev.anchor_sequence as unknown;
        if (typeof anc !== "number" || !Number.isInteger(anc as number) || (anc as number) < 1) {
          errors.push(`public/events.ndjson:${idx + 1} invalid anchor_sequence`);
        }
      }
      if ("metadata" in ev && (ev.metadata === null || typeof ev.metadata !== "object" || Array.isArray(ev.metadata))) {
        errors.push(`public/events.ndjson:${idx + 1} invalid metadata`);
      }
      if ("args" in ev && (ev.args === null || typeof ev.args !== "object" || Array.isArray(ev.args))) {
        errors.push(`public/events.ndjson:${idx + 1} invalid args`);
      }
      if ("output" in ev && (ev.output === null || typeof ev.output !== "object" || Array.isArray(ev.output))) {
        errors.push(`public/events.ndjson:${idx + 1} invalid output`);
      }
      if ("text" in ev) {
        const txt = ev.text as unknown;
        if (txt === null || typeof txt !== "object" || Array.isArray(txt) || !("$redacted" in (txt as Record<string, unknown>))) {
          errors.push(`public/events.ndjson:${idx + 1} invalid text`);
        }
      }
      if ("result" in ev) {
        const res = ev.result as unknown;
        if (res === null || typeof res !== "object" || Array.isArray(res) || !("$redacted" in (res as Record<string, unknown>))) {
          errors.push(`public/events.ndjson:${idx + 1} invalid result`);
        }
      }
      if ("annotation" in ev) {
        const ann = ev.annotation as unknown;
        if (ann === null || typeof ann !== "object" || Array.isArray(ann) || !("namespace" in (ann as Record<string, unknown>) && "kind" in (ann as Record<string, unknown>) && "payload" in (ann as Record<string, unknown>))) {
          errors.push(`public/events.ndjson:${idx + 1} invalid annotation`);
        }
      }
      if (hasUnsafeInt(ev)) {
        errors.push(`public/events.ndjson:${idx + 1} contains unsafe integer`);
      }
    }
  } catch (error) {
    errors.push(`event validation failed: ${String(error)}`);
  }
  return {
    ok: errors.length === 0,
    contentIdentity: errors.length === 0 ? (contentIdentity as string) : null,
    warnings,
    errors,
  };
}

// ---------------------------------------------------------------------------
// Projection helpers
// ---------------------------------------------------------------------------

function safeInt(value: unknown, fallback: number, minimum: number): number {
  if (typeof value === "number" && Number.isInteger(value) && value >= minimum) return value;
  return fallback;
}

/**
 * Read a live metadata field accepting both the web runtime's camelCase
 * emission and the canonical snake_case spelling (shared parity fixtures
 * and forward-compatible readers use the latter). camelCase wins on conflict.
 */
function metaField(metadata: Record<string, unknown>, camel: string, snake: string): unknown {
  const camelValue = metadata[camel];
  if (camelValue !== undefined) return camelValue;
  return metadata[snake];
}

function safeCategory(value: unknown): string {
  if (typeof value === "string" && value.length <= MAX_CATEGORY_LEN && /^[a-z][a-z0-9_]*$/.test(value)) {
    return value;
  }
  return "other";
}

function isMetricValue(value: unknown): boolean {
  if (typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  return false;
}

function outputReason(value: unknown): RedactionReason {
  return typeof value === "string" && (value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value))
    ? "absolute_path"
    : "private_content";
}

/** Safe byte count for a model response (content + tool-call args; never reasoning). */
export function responseBytes(response: {
  readonly content?: string | null;
  readonly toolCalls?: readonly { readonly arguments?: unknown }[];
}): number {
  let total = textEncoder.encode(response.content ?? "").length;
  for (const toolCall of response.toolCalls ?? []) {
    try {
      total += textEncoder.encode(canonicalStringify(toolCall.arguments ?? {})).length;
    } catch {
      continue;
    }
  }
  return total;
}
