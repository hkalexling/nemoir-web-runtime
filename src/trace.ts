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
export const RUNTIME_VERSION = "0.6.0";

export const MANIFEST_PATH = "manifest.json";
export const GRAPH_PATH = "public/workflow.graph.json";
export const EVENTS_PATH = "public/events.ndjson";
export const SUMMARY_PATH = "public/summary.json";
export const INTEGRITY_PATH = "integrity.json";
export const VAULT_ENC_PATH = "private/vault.enc";
export const VAULT_META_PATH = "private/vault.meta.json";
export const AUDIT_ENTRY_PATHS = [MANIFEST_PATH, GRAPH_PATH, EVENTS_PATH, SUMMARY_PATH] as const;
export const VAULT_ENTRY_PATHS = [VAULT_ENC_PATH, VAULT_META_PATH] as const;

export const VAULT_CODEC = "PBKDF2-HMAC-SHA-256+A256GCM";
export const VAULT_META_FORMAT = "nemoir.trace.vault-meta/0.1";
export const VAULT_AAD_FORMAT = "nemoir.trace.vault-aad/0.1";
export const VAULT_KDF_NAME = "PBKDF2-HMAC-SHA-256";
export const VAULT_KDF_ITERATIONS = 600_000;
export const VAULT_SALT_BYTES = 16;
export const VAULT_NONCE_BYTES = 12;
export const VAULT_DERIVED_KEY_BITS = 256;
export const VAULT_TAG_BITS = 128;
export const VAULT_PLAINTEXT_MEDIA_TYPE = "application/x-ndjson";
export const VAULT_NULL_IR_SHA256 = "sha256:" + "00".repeat(32);
export const DEFAULT_MAX_VAULT_BYTES = 64 * 1024 * 1024;

// Deterministic ZIP profile (matches the Phase 0 fixture assembly).
// Local-component construction so the DOS timestamp is always
// 1980-01-01 00:00:00 and never timezone-dependent; this also matches the
// Python writer's literal (1980, 1, 1, 0, 0, 0) tuple byte for byte.
const ZIP_EPOCH = /* @__PURE__ */ new Date(1980, 0, 1, 0, 0, 0);
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

export interface StageCompletedInfo {
  readonly stageId: string;
  readonly stageVisitId: string;
  readonly sequence: number;
}

export interface StageAnnotationSpec {
  readonly namespace: string;
  readonly kind: string;
  readonly payload: unknown;
  readonly anchorSequence?: number;
}

export interface VaultCapture {
  readonly includeModelMessages?: boolean;
  readonly includeToolResults?: boolean;
  readonly includeStageSnapshots?: boolean;
  readonly includeTransitionPolicy?: boolean;
  readonly includeReasoning?: boolean;
  readonly includeIr?: boolean;
  readonly maxVaultBytes?: number;
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
  /**
   * Narrow synchronous host hook invoked immediately after a successfully
   * observed `stage_completed` (Phase 3). Receives only stage/visit/sequence
   * and may return one annotation spec or null. Failures never break a run.
   */
  readonly onStageCompleted?: (info: StageCompletedInfo) => StageAnnotationSpec | null | undefined;
  readonly vaultPassphrase?: string | Uint8Array | null;
  readonly vaultCapture?: VaultCapture;
}

export interface VerificationReport {
  readonly ok: boolean;
  readonly contentIdentity: string | null;
  readonly warnings: readonly string[];
  readonly errors: readonly string[];
  readonly integrity: string;
  readonly structural: string;
  readonly semantic: string;
  readonly replayability: string;
}

export function policyRefsFor(policies: readonly { id: string }[] | null | undefined): Map<string, string> {
  const refs = new Map<string, string>();
  let index = 1;
  for (const policy of policies ?? []) {
    const maybe = policy as unknown as { id?: unknown } | Record<string, unknown>;
    const pid = typeof (maybe as Record<string, unknown>)["id"] === "string"
      ? (maybe as Record<string, unknown>)["id"] as string
      : (maybe as { id?: unknown }).id;
    if (typeof pid === "string" && !refs.has(pid)) {
      refs.set(pid, `p-${index}`);
    }
    index += 1;
  }
  return refs;
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

export class SecretRegistry {
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
      // An already-markered value is neutralized: the key name alone
      // (declared in the workflow's public writes schema) is not a leak.
      // Reporting it would loop the mask passes until the whole record is
      // omitted — dropping milestone events taped replay needs for path
      // comparison. Raw values stay reportable below.
      if (isRedactionMarker(nodeAtPointer(node, childPointer))) continue;
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
// Vault helpers (Phase 4)
// ---------------------------------------------------------------------------

export const _VAULT_CREDENTIAL_KEYS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "api_key",
  "api-key",
  "apikey",
  "access_token",
  "refresh_token",
  "client_secret",
  "extra_headers",
  "default_headers",
  "headers",
]);

const _VAULT_RECORD_TYPES = new Set([
  "run_inputs",
  "stage_snapshot",
  "model_request",
  "model_response",
  "tool_result",
  "transition_evaluation",
  "policy_evaluation",
  "private_fields",
  "full_workflow_ir",
  "annotation_private_fields",
]);

export function normalizePassphrase(value: string | Uint8Array | null | undefined): Uint8Array | null {
  if (value === null || value === undefined) return null;
  let text: string;
  if (value instanceof Uint8Array) {
    try {
      text = textDecoder.decode(value);
    } catch {
      throw new TraceError("vault passphrase must be valid UTF-8");
    }
  } else {
    text = value;
  }
  if (text.length === 0) return null;
  const normalized = text.normalize("NFC");
  return textEncoder.encode(normalized);
}

function b64urlEncode(raw: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < raw.length; i++) binary += String.fromCharCode(raw[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(value: string, what: string, expected?: number): Uint8Array {
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  let binary: string;
  try {
    binary = atob(base64);
  } catch {
    throw new TraceError(`vault metadata has invalid base64url for ${what}`);
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  if (expected !== undefined && out.length !== expected) {
    throw new TraceError(`vault metadata has invalid length for ${what}`);
  }
  return out;
}

export function _toJsonable(value: unknown, depth = 0): unknown {
  if (depth > 64) throw new TraceError("vault value exceeds nesting depth");
  if (value === null || value === undefined || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TraceError("vault value has non-finite number");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) throw new TraceError(`vault value has unsafe integer ${JSON.stringify(value)}`);
    return value;
  }
  if (value instanceof Uint8Array) return textDecoder.decode(value);
  if (value instanceof ArrayBuffer) return textDecoder.decode(new Uint8Array(value));
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Map) {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of value.entries()) {
      obj[String(k)] = _toJsonable(v, depth + 1);
    }
    return obj;
  }
  if (value instanceof Set) {
    const arr = [...value].map((v) => _toJsonable(v, depth + 1));
    return arr.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  }
  if (Array.isArray(value)) return (value as unknown[]).map((v) => _toJsonable(v, depth + 1));
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    // Detect plain object vs class - still convert keys
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(record)) {
      out[k] = _toJsonable(v, depth + 1);
    }
    return out;
  }
  throw new TraceError(`vault value of type ${typeof value} is not serializable`);
}

function nodeAtPointer(node: unknown, pointer: string): unknown {
  if (pointer === "" || pointer === "/") return node;
  let current: unknown = node;
  for (const part of pointer.split("/").slice(1)) {
    const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
    if (current !== null && typeof current === "object" && !Array.isArray(current)) {
      const map = current as Record<string, unknown>;
      if (!(key in map)) return null;
      current = map[key];
    } else if (Array.isArray(current)) {
      if (!/^\d+$/.test(key) || Number(key) >= (current as unknown[]).length) return null;
      current = (current as unknown[])[Number(key)];
    } else {
      return null;
    }
  }
  return current;
}

function isRedactionMarker(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  return "$redacted" in (value as Record<string, unknown>) && typeof (value as Record<string, unknown>)["$redacted"] === "object";
}

function vaultFindingExcused(record: Record<string, unknown>, finding: Finding): boolean {
  if (isRedactionMarker(nodeAtPointer(record, finding.pointer))) return true;
  if (finding.rule === "prohibited_field") {
    const key = finding.pointer.split("/").pop()!.replace(/~1/g, "/").replace(/~0/g, "~");
    return !_VAULT_CREDENTIAL_KEYS.has(key.toLowerCase());
  }
  return false;
}

function vaultRecordShapeError(record: unknown): string | null {
  if (record === null || typeof record !== "object" || Array.isArray(record)) return "vault record must be an object";
  const entry = record as Record<string, unknown>;
  if (typeof entry.record_id !== "string" || !/^v-[1-9][0-9]*$/.test(entry.record_id)) return `vault record has invalid record_id ${JSON.stringify(entry.record_id)}`;
  if (!_VAULT_RECORD_TYPES.has(entry.record_type as string)) return `vault record has invalid record_type ${JSON.stringify(entry.record_type)}`;
  return null;
}

function vaultMetaObject(params: { salt: Uint8Array; nonce: Uint8Array; aadDict: Record<string, unknown> }): Record<string, unknown> {
  return {
    format: VAULT_META_FORMAT,
    codec: VAULT_CODEC,
    passphrase: { encoding: "UTF-8", normalization: "NFC" },
    kdf: {
      name: VAULT_KDF_NAME,
      iterations: VAULT_KDF_ITERATIONS,
      salt_base64url: b64urlEncode(params.salt),
      derived_key_bits: VAULT_DERIVED_KEY_BITS,
    },
    cipher: {
      name: "AES-256-GCM",
      nonce_base64url: b64urlEncode(params.nonce),
      tag_length_bits: VAULT_TAG_BITS,
      tag_placement: "ciphertext_suffix",
    },
    plaintext: {
      media_type: VAULT_PLAINTEXT_MEDIA_TYPE,
      encoding: "UTF-8",
      compression: "none",
    },
    aad: params.aadDict,
  };
}

async function deriveVaultKey(passphrase: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey("raw", passphrase as unknown as ArrayBuffer, { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as unknown as ArrayBuffer, iterations: VAULT_KDF_ITERATIONS },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptVaultRecords(
  plaintext: Uint8Array,
  passphrase: Uint8Array,
  aad: Uint8Array,
  opts: { salt?: Uint8Array; nonce?: Uint8Array } = {},
): Promise<{ salt: Uint8Array; nonce: Uint8Array; sealed: Uint8Array }> {
  const salt = opts.salt ?? crypto.getRandomValues(new Uint8Array(VAULT_SALT_BYTES));
  const nonce = opts.nonce ?? crypto.getRandomValues(new Uint8Array(VAULT_NONCE_BYTES));
  if (salt.length !== VAULT_SALT_BYTES || nonce.length !== VAULT_NONCE_BYTES) throw new TraceError("vault salt/nonce have invalid length");
  const key = await deriveVaultKey(passphrase, salt);
  const sealedBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as unknown as ArrayBuffer, additionalData: aad as unknown as ArrayBuffer, tagLength: 128 }, key, plaintext as unknown as ArrayBuffer);
  return { salt, nonce, sealed: new Uint8Array(sealedBuf) };
}

export async function decryptVaultRecords(
  sealed: Uint8Array,
  passphrase: Uint8Array,
  aad: Uint8Array,
  params: { salt: Uint8Array; nonce: Uint8Array },
): Promise<Uint8Array> {
  if (params.salt.length !== VAULT_SALT_BYTES || params.nonce.length !== VAULT_NONCE_BYTES) throw new TraceError("vault unlock failed");
  if (sealed.length < 16) throw new TraceError("vault unlock failed");
  const key = await deriveVaultKey(passphrase, params.salt);
  try {
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: params.nonce as unknown as ArrayBuffer, additionalData: aad as unknown as ArrayBuffer, tagLength: 128 }, key, sealed as unknown as ArrayBuffer);
    return new Uint8Array(plainBuf);
  } catch {
    throw new TraceError("vault unlock failed");
  }
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

// ---------------------------------------------------------------------------
// Trusted autoresearch annotation validation (Phase 3)
// ---------------------------------------------------------------------------

export const ANNOTATION_NAMESPACE = "nemoir.autoresearch/v1";
export const ANNOTATION_KIND = "trial_finished";

const ANNOTATION_VERDICTS = new Set(["accepted", "rejected", "inconclusive"]);

const ANNOTATION_REASONS = new Set([
  "accepted",
  "no_change",
  "duplicate",
  "preflight_integrity",
  "preflight_scope",
  "preflight_static_scan",
  "preflight_build",
  "preflight_smoke",
  "preflight_sanitizer",
  "selection_correctness",
  "selection_noise",
  "selection_tail_regression",
  "confirmation_correctness",
  "confirmation_noise",
  "confirmation_tail_regression",
  "no_improvement",
  "full_sanitizer",
  "no_evaluation",
  "policy_denied",
  "tool_failed",
  "budget_exhausted",
  "other",
]);

const ANNOTATION_METRIC_NUMBERS = new Set([
  "candidate_median_ns",
  "incumbent_median_ns",
  "delta_ns",
  "effect_ns",
  "speedup_pct",
  "candidate_spread_pct",
  "p95_regression_pct",
  "cold_regression_pct",
]);

const ANNOTATION_METRIC_BOOLS = new Set(["valid", "noise_ok", "regressions_ok"]);

const ANNOTATION_REQUIRED = new Set([
  "trial_id",
  "candidate_ref",
  "verdict",
  "reason_code",
  "selection_metrics",
  "artifact_refs",
]);

const ANNOTATION_ALLOWED = new Set([
  "trial_id",
  "candidate_ref",
  "parent_ref",
  "candidate_digest",
  "parent_digest",
  "selection_metrics",
  "confirmation_metrics",
  "verdict",
  "reason_code",
  "source_reason_code",
  "mechanism_ref",
  "mechanism_id",
  "artifact_refs",
]);

function validateAutoresearchMetrics(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TraceError(`trial_finished payload has invalid ${field}: must be an object`);
  }
  const mapping = { ...(value as Record<string, unknown>) };
  for (const key of Object.keys(mapping)) {
    if (!ANNOTATION_METRIC_NUMBERS.has(key) && !ANNOTATION_METRIC_BOOLS.has(key)) {
      throw new TraceError(`trial_finished payload has unknown metrics field ${JSON.stringify(key)} in ${field}`);
    }
  }
  for (const key of ANNOTATION_METRIC_NUMBERS) {
    if (!(key in mapping)) continue;
    const number = mapping[key];
    if (typeof number !== "number" || !Number.isFinite(number)) {
      throw new TraceError(`trial_finished payload has invalid ${field}.${key}: must be a finite number`);
    }
    if (Number.isInteger(number) && !Number.isSafeInteger(number)) {
      throw new TraceError(`trial_finished payload has unsafe integer ${field}.${key}`);
    }
  }
  for (const key of ANNOTATION_METRIC_BOOLS) {
    if (!(key in mapping)) continue;
    if (typeof mapping[key] !== "boolean") {
      throw new TraceError(`trial_finished payload has invalid ${field}.${key}: must be a boolean`);
    }
  }
  return mapping;
}

export function validateAutoresearchPayload(payload: unknown): Record<string, unknown> {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new TraceError("trial_finished payload must be an object");
  }
  const data: Record<string, unknown> = { ...(payload as Record<string, unknown>) };
  for (const key of Object.keys(data)) {
    if (!ANNOTATION_ALLOWED.has(key)) {
      throw new TraceError(`trial_finished payload has unknown field ${JSON.stringify(key)}`);
    }
  }
  for (const key of ANNOTATION_REQUIRED) {
    if (!(key in data)) {
      throw new TraceError(`trial_finished payload is missing field ${JSON.stringify(key)}`);
    }
  }
  const trialId = data.trial_id;
  if (typeof trialId !== "number" || !Number.isInteger(trialId) || !Number.isSafeInteger(trialId) || trialId < 1) {
    throw new TraceError(`trial_finished payload has invalid trial_id ${JSON.stringify(trialId)}`);
  }
  if (typeof data.candidate_ref !== "string" || !/^candidate-[1-9][0-9]*$/.test(data.candidate_ref)) {
    throw new TraceError(`trial_finished payload has invalid candidate_ref ${JSON.stringify(data.candidate_ref)}`);
  }
  const parentRef = data.parent_ref;
  if (parentRef !== undefined && parentRef !== null) {
    if (typeof parentRef !== "string" || !/^candidate-[1-9][0-9]*$/.test(parentRef)) {
      throw new TraceError(`trial_finished payload has invalid parent_ref ${JSON.stringify(parentRef)}`);
    }
  }
  for (const digestKey of ["candidate_digest", "parent_digest"] as const) {
    const digest = data[digestKey];
    if (digest !== undefined && digest !== null) {
      if (typeof digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(digest)) {
        throw new TraceError(`trial_finished payload has invalid ${digestKey} ${JSON.stringify(digest)}`);
      }
    }
  }
  data.selection_metrics = validateAutoresearchMetrics(data.selection_metrics, "selection_metrics");
  if (data.confirmation_metrics !== undefined && data.confirmation_metrics !== null) {
    data.confirmation_metrics = validateAutoresearchMetrics(data.confirmation_metrics, "confirmation_metrics");
  }
  if (!ANNOTATION_VERDICTS.has(data.verdict as string)) {
    throw new TraceError(`trial_finished payload has invalid verdict ${JSON.stringify(data.verdict)}`);
  }
  if (!ANNOTATION_REASONS.has(data.reason_code as string)) {
    throw new TraceError(`trial_finished payload has invalid reason_code ${JSON.stringify(data.reason_code)}`);
  }
  const sourceReason = data.source_reason_code;
  if (sourceReason !== undefined && sourceReason !== null) {
    if (typeof sourceReason !== "string" || sourceReason.length > 64 || !/^[a-z0-9][a-z0-9_-]*$/.test(sourceReason)) {
      throw new TraceError(`trial_finished payload has invalid source_reason_code ${JSON.stringify(sourceReason)}`);
    }
  }
  const mechanismRef = data.mechanism_ref;
  if (mechanismRef !== undefined && mechanismRef !== null) {
    if (typeof mechanismRef !== "string" || !/^mechanism-[1-9][0-9]*$/.test(mechanismRef)) {
      throw new TraceError(`trial_finished payload has invalid mechanism_ref ${JSON.stringify(mechanismRef)}`);
    }
  }
  const mechanismId = data.mechanism_id;
  if (mechanismId !== undefined && mechanismId !== null) {
    if (typeof mechanismId !== "string" || mechanismId.length < 1 || mechanismId.length > 128) {
      throw new TraceError("trial_finished payload has invalid mechanism_id");
    }
  }
  const artifactRefs = data.artifact_refs;
  if (!Array.isArray(artifactRefs)) {
    throw new TraceError("trial_finished payload has invalid artifact_refs: must be an array");
  }
  if (new Set(artifactRefs).size !== artifactRefs.length) {
    throw new TraceError("trial_finished payload has duplicate artifact_refs");
  }
  for (const ref of artifactRefs) {
    if (typeof ref !== "string" || !/^artifact-[1-9][0-9]*$/.test(ref)) {
      throw new TraceError(`trial_finished payload has invalid artifact_ref ${JSON.stringify(ref)}`);
    }
  }
  data.artifact_refs = [...artifactRefs];
  return data;
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
  readonly onStageCompleted?: (info: StageCompletedInfo) => StageAnnotationSpec | null | undefined;
  readonly vaultPassphrase: Uint8Array | null;
  readonly vaultCapture: Required<VaultCapture>;
}

function defaultVaultCapture(): Required<VaultCapture> {
  return {
    includeModelMessages: true,
    includeToolResults: true,
    includeStageSnapshots: true,
    includeTransitionPolicy: true,
    includeReasoning: false,
    includeIr: true,
    maxVaultBytes: DEFAULT_MAX_VAULT_BYTES,
  };
}

function normalizeVaultCapture(input?: VaultCapture): Required<VaultCapture> {
  const def = defaultVaultCapture();
  if (!input) return def;
  return {
    includeModelMessages: input.includeModelMessages ?? def.includeModelMessages,
    includeToolResults: input.includeToolResults ?? def.includeToolResults,
    includeStageSnapshots: input.includeStageSnapshots ?? def.includeStageSnapshots,
    includeTransitionPolicy: input.includeTransitionPolicy ?? def.includeTransitionPolicy,
    includeReasoning: input.includeReasoning ?? def.includeReasoning,
    includeIr: input.includeIr ?? def.includeIr,
    maxVaultBytes: input.maxVaultBytes ?? def.maxVaultBytes,
  };
}

function normalizeConfig(config: TraceConfig = {}): RecorderConfig {
  const profile = config.profile ?? "audit";
  if (profile !== "audit" && profile !== "replay") {
    throw new TraceError(
      `unsupported trace profile '${profile}': expected 'audit' or 'replay' (publication arrives in Phase 5)`,
    );
  }
  const vaultPassphrase = normalizePassphrase(config.vaultPassphrase ?? null);
  const vaultCapture = normalizeVaultCapture(config.vaultCapture);
  if (profile === "replay" && vaultPassphrase === null) {
    throw new TraceError("trace profile 'replay' requires vaultPassphrase");
  }
  if (profile !== "replay" && vaultPassphrase !== null) {
    throw new TraceError("vaultPassphrase requires trace profile 'replay'");
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
    onStageCompleted: config.onStageCompleted,
    vaultPassphrase,
    vaultCapture,
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
  // Last model-call id bound to a ledger record in each visit. A retry
  // emitted after model_completed consumed the pending id reuses this
  // instead of synthesizing a dangling id with no vault evidence.
  private readonly lastModelId = new Map<string, string>();
  private readonly pendingTools = new Map<string, string[]>();
  private readonly openTools = new Map<string, string[]>();
  private currentVisit: string | null = null;
  private currentStageId: string | null = null;
  private readonly visitToStage = new Map<string, string>();
  private readonly visitSequences = new Map<string, number[]>();
  private annotationsDropped = 0;
  private readonly annotationWarnings: string[] = [];
  private readonly modelBytes = new Map<string, number>();
  private readonly modelToolCalls = new Map<string, number>();
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
  // Vault state
  private readonly openToolCalls = new Map<string, Record<string, unknown>>();
  private readonly vaultRecords: Record<string, unknown>[] = [];
  private vaultCount = 0;
  private readonly pendingTransitions = new Map<string, { candidates: Record<string, unknown>[] }[]>();

  constructor(config: TraceConfig = {}) {
    this.config = normalizeConfig(config);
    this.registry = new SecretRegistry(this.config.secrets);
  }

  get vault_enabled(): boolean {
    return this.config.profile === "replay";
  }

  get vaultEnabled(): boolean {
    return this.vault_enabled;
  }

  /** Optional taped policy outcomes for replay (see replay.ts). Maps policy id to recorded outcomes FIFO. Null means live evaluation. */
  policyTape: Map<string, string[]> | Record<string, string[]> | null = null;

  consumeTapedPolicy(policyId: unknown): string | null {
    const tape: unknown = (this as unknown as { policyTape: unknown }).policyTape;
    if (tape === null || tape === undefined || typeof policyId !== "string") return null;
    let queue: string[] | undefined;
    if (tape instanceof Map) queue = (tape as Map<string, string[]>).get(policyId);
    else queue = (tape as Record<string, string[]>)[policyId];
    if (!queue || queue.length === 0) return null;
    return queue.shift()!;
  }

  get traceId(): string {
    return this.config.traceId;
  }

  get droppedAnnotations(): number {
    return this.annotationsDropped;
  }

  get droppedAnnotationWarnings(): readonly string[] {
    return [...this.annotationWarnings];
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
    for (const [pid, ref] of policyRefsFor(manifest.policies as unknown as { id: string }[])) {
      if (!this.policyRefs.has(pid)) this.policyRefs.set(pid, ref);
    }
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
    this.currentStageId = stageId;
    this.visitToStage.set(visitId, stageId);
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

  recordModelRequest(modelCallId: string, request: Record<string, unknown> | null | undefined): void {
    this.requireBegun();
    if (!this.vault_enabled || request === null || request === undefined) return;
    if (!this.config.vaultCapture.includeModelMessages) return;
    const payload = _toJsonable({ ...request }) as Record<string, unknown>;
    const scrubbed = this.scrubVaultValue(payload);
    this.appendVaultRecord("model_request", scrubbed, { modelCallId, stageVisitId: this.currentVisit ?? undefined });
  }

  /** Record safe model-response facts (counts only, never text). */
  recordModelResponse(
    modelCallId: string,
    facts: { responseBytes?: number; toolCallCount?: number; response?: Record<string, unknown> | null } = {},
  ): void {
    this.requireBegun();
    this.modelBytes.set(modelCallId, Math.max(0, Math.trunc(facts.responseBytes ?? 0)));
    this.modelToolCalls.set(modelCallId, Math.max(0, Math.trunc(facts.toolCallCount ?? 0)));
    if (!this.vault_enabled || facts.response === null || facts.response === undefined) return;
    if (!this.config.vaultCapture.includeModelMessages) return;
    const payload = _toJsonable({ ...facts.response }) as Record<string, unknown>;
    if (!this.config.vaultCapture.includeReasoning) {
      const reasoning = payload["reasoning"];
      delete payload["reasoning"];
      const isEmptyReasoning =
        reasoning === null ||
        reasoning === undefined ||
        reasoning === "" ||
        (Array.isArray(reasoning) && reasoning.length === 0) ||
        (typeof reasoning === "object" && reasoning !== null && !Array.isArray(reasoning) && Object.keys(reasoning as Record<string, unknown>).length === 0);
      if (!isEmptyReasoning) {
        payload["reasoning"] = this.newMarker("private_content", reasoning);
      }
    }
    const scrubbed = this.scrubVaultValue(payload);
    this.appendVaultRecord("model_response", scrubbed, { modelCallId, stageVisitId: this.currentVisit ?? undefined });
  }

  recordRunInputs(inputs: Record<string, unknown> | null | undefined): void {
    this.requireBegun();
    if (!this.vault_enabled || inputs === null || inputs === undefined) return;
    const payload = _toJsonable({ ...inputs });
    const scrubbed = this.scrubVaultValue(payload);
    this.appendVaultRecord("run_inputs", scrubbed);
  }

  recordPolicyEvaluation(
    stageVisitId: string | null | undefined,
    policyId: unknown,
    bound: Record<string, unknown> | null | undefined,
    outcome: string,
  ): void {
    this.requireBegun();
    if (!this.vault_enabled) return;
    if (!this.config.vaultCapture.includeTransitionPolicy) return;
    if (outcome !== "allowed" && outcome !== "denied") throw new TraceError(`policy evaluation outcome must be allowed/denied, got ${JSON.stringify(outcome)}`);
    const ref = this.policyRef(policyId);
    const payload: Record<string, unknown> = {
      policy_ref: ref,
      outcome,
      bound: this.scrubVaultValue(_toJsonable({ ...(bound ?? {}) })),
    };
    if (ref === null) payload["policy_ref"] = this.newMarker("private_content", policyId);
    this.appendVaultRecord("policy_evaluation", payload, { stageVisitId: (stageVisitId ?? this.currentVisit) ?? undefined });
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
  recordToolResult(toolCallId: string, result: unknown, args?: Record<string, unknown> | null): void {
    this.requireBegun();
    this.toolErrors.delete(toolCallId);
    this.toolResultTypes.set(toolCallId, resultTypeSlug(result));
    if (!this.vault_enabled) return;
    if (!this.config.vaultCapture.includeToolResults) return;
    const stashed = this.openToolCalls.get(toolCallId) ?? {};
    const effectiveArgs = args ?? (stashed["args"] as Record<string, unknown> | undefined);
    const payload: Record<string, unknown> = { result: _toJsonable(result) };
    if (effectiveArgs !== null && effectiveArgs !== undefined) payload["args"] = _toJsonable({ ...effectiveArgs }) as unknown;
    if (stashed["capability"] !== undefined) payload["capability"] = stashed["capability"];
    if (stashed["tool_name"] !== undefined) payload["tool_name"] = stashed["tool_name"];
    const scrubbed = this.scrubVaultValue(payload);
    this.appendVaultRecord("tool_result", scrubbed, { toolCallId, stageVisitId: this.currentVisit ?? undefined });
  }

  /** Capture a tool failure's stable error taxonomy (no message). */
  recordToolError(toolCallId: string, exc: unknown): void {
    this.requireBegun();
    const stable = stableError(exc);
    this.toolErrors.set(toolCallId, stable);
    if (!this.vault_enabled) return;
    if (!this.config.vaultCapture.includeToolResults) return;
    let message = "";
    try {
      message = String((exc as Error)?.message ?? String(exc)).slice(0, 4000);
    } catch {
      message = "";
    }
    const stashed = this.openToolCalls.get(toolCallId) ?? {};
    const payload: Record<string, unknown> = {
      error: { code: stable.code, type: stable.typeName },
      message: this.scrubVaultValue(message),
    };
    if (stashed["args"] !== undefined) payload["args"] = this.scrubVaultValue(_toJsonable({ ...(stashed["args"] as Record<string, unknown>) }));
    if (stashed["capability"] !== undefined) payload["capability"] = stashed["capability"];
    this.appendVaultRecord("tool_result", payload, { toolCallId, stageVisitId: this.currentVisit ?? undefined });
  }

  /**
   * Retain guard-evaluation evidence for future semantic verification.
   * Phase 1 keeps this in memory only; the audit ledger publishes the
   * selected transition while full candidate evidence ships with the
   * Phase 4 vault.
   */
  recordTransitionEvaluation(stageVisitId: string, candidates: readonly unknown[]): void {
    this.requireBegun();
    const cleaned: Record<string, unknown>[] = [];
    for (const raw of candidates as unknown[]) {
      if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new TraceError("transition candidate must be an object");
      const m = raw as Record<string, unknown>;
      const to = m["to"];
      if (typeof to !== "string") throw new TraceError("transition candidate requires a string 'to'");
      cleaned.push({
        to,
        priority: Math.max(0, Math.trunc((m["priority"] as number) ?? 0) || 0),
        reason: (m["reason"] as string) ?? "other",
        matched: Boolean(m["matched"]),
      });
    }
    this.transitionEvidence.push({ stageVisitId, candidates: cleaned });
    if (!this.vault_enabled) return;
    if (!this.config.vaultCapture.includeTransitionPolicy) return;
    const pending = this.pendingTransitions.get(stageVisitId) ?? [];
    pending.push({ candidates: cleaned });
    this.pendingTransitions.set(stageVisitId, pending);
  }

  private appendVaultRecord(
    recordType: string,
    payload: unknown,
    opts: { eventSequence?: number; stageVisitId?: string; modelCallId?: string; toolCallId?: string } = {},
  ): Record<string, unknown> {
    if (!_VAULT_RECORD_TYPES.has(recordType)) throw new TraceError(`unknown vault record type ${JSON.stringify(recordType)}`);
    this.vaultCount += 1;
    const record: Record<string, unknown> = {
      record_id: `v-${this.vaultCount}`,
      record_type: recordType,
      payload,
    };
    if (opts.eventSequence !== undefined) record["event_sequence"] = opts.eventSequence;
    if (opts.stageVisitId !== undefined) record["stage_visit_id"] = opts.stageVisitId;
    if (opts.modelCallId !== undefined) record["model_call_id"] = opts.modelCallId;
    if (opts.toolCallId !== undefined) record["tool_call_id"] = opts.toolCallId;
    this.vaultRecords.push(record);
    return record;
  }

  private scrubVaultValue(value: unknown): unknown {
    const scrubbed = this.scrubVaultNode(value);
    const wrapper: Record<string, unknown> = { v: scrubbed };
    for (let i = 0; i < MAX_MASK_PASSES; i++) {
      const hits = scanStrings(wrapper, "", this.registry).filter((f) => f.rule === "registered_secret");
      if (hits.length === 0) break;
      this.setMarker(wrapper, hits[0].pointer, "credential");
    }
    // If still hits, replace whole value
    if (scanStrings(wrapper, "", this.registry).some((f) => f.rule === "registered_secret")) {
      wrapper["v"] = this.newMarker("credential", wrapper["v"]);
    }
    for (let i = 0; i < MAX_MASK_PASSES; i++) {
      const findings = scanStrings(wrapper, "", this.registry).filter((f) => f.rule !== "registered_secret" && !vaultFindingExcused(wrapper as Record<string, unknown>, f));
      if (findings.length === 0) break;
      const finding = findings[0];
      let reason: RedactionReason = "unapproved_field";
      if (finding.rule === "home_path") reason = "absolute_path";
      else if (CREDENTIAL_RULES.has(finding.rule)) reason = "credential";
      this.setMarker(wrapper, finding.pointer, reason);
    }
    if (scanStrings(wrapper, "", this.registry).some((f) => f.rule !== "registered_secret" && !vaultFindingExcused(wrapper as Record<string, unknown>, f))) {
      wrapper["v"] = this.newMarker("credential", wrapper["v"]);
    }
    const result = wrapper["v"];
    // cleanup omit flag if any (not needed)
    if (typeof result === "object" && result !== null && "_omit" in (result as Record<string, unknown>)) {
      delete (result as Record<string, unknown>)["_omit"];
    }
    return result;
  }

  private scrubVaultNode(value: unknown): unknown {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const mapping = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const [rawKey, rawItem] of Object.entries(mapping)) {
        const lowered = rawKey.toLowerCase();
        if (_VAULT_CREDENTIAL_KEYS.has(lowered)) {
          out[rawKey] = this.newMarker("credential", rawItem);
        } else {
          out[rawKey] = this.scrubVaultNode(rawItem);
        }
      }
      return out;
    }
    if (Array.isArray(value)) return (value as unknown[]).map((v) => this.scrubVaultNode(v));
    if (typeof value === "string") return this.scrubVaultText(value);
    return value;
  }

  private scrubVaultText(text: string): unknown {
    // Try alias matching using string prefix (web pathAliases are string prefixes)
    const aliases = Object.entries(this.config.pathAliases).sort(([ ,a],[ ,b]) => b.length - a.length);
    for (const [alias, root] of aliases) {
      if (text === root || text.startsWith(`${root}/`)) {
        const relative = text === root ? "" : text.slice(root.length + 1);
        if (this.config.safePathAliases.has(alias)) {
          return relative ? `${alias}/${relative}` : alias;
        }
        let ref = this.pathRefs.get(text);
        if (ref === undefined) {
          this.pathRefCount += 1;
          ref = `path-${this.pathRefCount}`;
          this.pathRefs.set(text, ref);
        }
        return ref;
      }
    }
    // Unregistered absolute path -> opaque ref (detect via leading /)
    if (text.startsWith("/") && text.length > 1) {
      let ref = this.pathRefs.get(text);
      if (ref === undefined) {
        this.pathRefCount += 1;
        ref = `path-${this.pathRefCount}`;
        this.pathRefs.set(text, ref);
      }
      return ref;
    }
    return text;
  }

  // Python parity aliases (underscore prefix) for WS2 surface checks
  _scrubVaultValue(value: unknown): unknown { return this.scrubVaultValue(value); }
  _scrubVaultNode(value: unknown): unknown { return this.scrubVaultNode(value); }
  _scrubVaultText(text: string): unknown { return this.scrubVaultText(text); }

  /**
   * Persist one trusted domain annotation (Phase 3). Known
   * `nemoir.autoresearch/v1` / `trial_finished` payloads are strictly
   * validated; unknown namespaces retain only namespace/kind with a redacted
   * payload marker. Returns the persisted record, or null when the scanner
   * forces omission. Throws on malformed known payloads or missing context.
   */
  recordAnnotation(
    namespace: string,
    kind: string,
    payload?: unknown,
    anchorSequence?: number,
    opts: { stageId?: string; stageVisitId?: string } = {},
  ): Record<string, unknown> | null {
    this.requireBegun();
    if (this.eventLimitExceeded || this.events.length >= LIMIT_EVENT_COUNT) {
      this.eventLimitExceeded = true;
      return null;
    }
    const visit = opts.stageVisitId ?? this.currentVisit;
    const stage = opts.stageId ?? (visit !== null ? (this.visitToStage.get(visit) ?? this.currentStageId) : null);
    if (visit === null || stage === null || stage === undefined) {
      throw new TraceError("trace annotation requires an enclosing stage visit");
    }
    if (!/^s-[1-9][0-9]*$/.test(visit)) {
      throw new TraceError(`trace annotation has invalid stage_visit_id ${JSON.stringify(visit)}`);
    }
    if (typeof stage !== "string" || stage.length < 1 || stage.length > 256) {
      throw new TraceError(`trace annotation has invalid stage_id ${JSON.stringify(stage)}`);
    }
    if (anchorSequence !== undefined && anchorSequence !== null) {
      if (typeof anchorSequence !== "number" || !Number.isInteger(anchorSequence) || !Number.isSafeInteger(anchorSequence) || anchorSequence < 1) {
        throw new TraceError(`trace annotation has invalid anchor_sequence ${JSON.stringify(anchorSequence)}`);
      }
      const known = this.visitSequences.get(visit) ?? [];
      if (known.length > 0 && !known.includes(anchorSequence)) {
        throw new TraceError(`trace annotation anchor_sequence ${JSON.stringify(anchorSequence)} does not belong to visit ${JSON.stringify(visit)}`);
      }
    }
    let projectedPayload: unknown;
    if (namespace === ANNOTATION_NAMESPACE && kind === ANNOTATION_KIND) {
      if (payload === undefined || payload === null) {
        throw new TraceError("trial_finished annotation requires a payload mapping");
      }
      projectedPayload = validateAutoresearchPayload(payload);
      // Audit policy gate (redaction-policy §11): digests and raw mechanism
      // IDs require explicit publication review; audit keeps opaque refs only.
      if (this.config.profile === "audit" && typeof projectedPayload === "object" && projectedPayload !== null && !Array.isArray(projectedPayload)) {
        const pp = projectedPayload as Record<string, unknown>;
        if (pp.candidate_digest !== null && pp.candidate_digest !== undefined) {
          throw new TraceError("audit profile rejects non-null candidate_digest (requires publication review)");
        }
        if (pp.parent_digest !== null && pp.parent_digest !== undefined) {
          throw new TraceError("audit profile rejects non-null parent_digest (requires publication review)");
        }
        if (pp.mechanism_id !== null && pp.mechanism_id !== undefined) {
          throw new TraceError("audit profile rejects non-null mechanism_id (requires publication review)");
        }
      }
    } else {
      projectedPayload = this.newMarker("unapproved_field", payload ?? {});
    }
    const record: Record<string, unknown> = {
      kind: "annotation",
      run_id: this.config.traceId,
      timestamp: this.config.clock().toISOString(),
      stage_id: stage,
      stage_visit_id: visit,
      annotation: { namespace, kind, payload: projectedPayload },
      redacted_fields: [],
    };
    if (anchorSequence !== undefined && anchorSequence !== null) {
      record.anchor_sequence = anchorSequence;
    }
    if (projectedPayload !== null && typeof projectedPayload === "object" && !Array.isArray(projectedPayload) && "$redacted" in (projectedPayload as Record<string, unknown>)) {
      record.redacted_fields = ["/annotation/payload"];
    }
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
    const visitSeq = (record as Record<string, unknown>).stage_visit_id;
    if (typeof visitSeq === "string" && typeof event.sequence === "number" && Number.isInteger(event.sequence) && event.sequence >= 1) {
      const arr = this.visitSequences.get(visitSeq) ?? [];
      arr.push(event.sequence);
      this.visitSequences.set(visitSeq, arr);
    }
    if ((record as Record<string, unknown>).kind === "stage_completed") {
      this.captureStageSnapshot(record, event);
      this.maybeEmitStageAnnotation(record, event);
    }
    if ((record as Record<string, unknown>).kind === "transition_selected") {
      this.flushTransitionEvidence(record, event);
    }
    return record;
  }

  private captureStageSnapshot(record: Record<string, unknown>, event: WorkflowEvent): void {
    if (!this.vault_enabled) return;
    if (!this.config.vaultCapture.includeStageSnapshots) return;
    let payload: Record<string, unknown>;
    try {
      payload = {
        stage_id: event.stageId ?? (record["stage_id"] as string),
        output: this.scrubVaultValue(_toJsonable({ ...(event.output ?? {}) })),
      };
    } catch {
      payload = {
        stage_id: event.stageId ?? (record["stage_id"] as string),
        output: this.newMarker("private_content", event.output ?? {}),
      };
    }
    const seq = typeof event.sequence === "number" && Number.isInteger(event.sequence) && event.sequence >= 1 ? event.sequence : undefined;
    this.appendVaultRecord("stage_snapshot", payload, { eventSequence: seq, stageVisitId: record["stage_visit_id"] as string });
  }

  private flushTransitionEvidence(record: Record<string, unknown>, event: WorkflowEvent): void {
    if (!this.vault_enabled) return;
    const visit = record["stage_visit_id"] as string;
    if (typeof visit !== "string") return;
    const pending = this.pendingTransitions.get(visit);
    if (!pending || pending.length === 0) return;
    this.pendingTransitions.delete(visit);
    const seq = typeof event.sequence === "number" && Number.isInteger(event.sequence) && event.sequence >= 1 ? event.sequence : undefined;
    for (const item of pending) {
      this.appendVaultRecord("transition_evaluation", { candidates: item.candidates }, { eventSequence: seq, stageVisitId: visit });
    }
  }

  private recordAnnotationWarning(record: Record<string, unknown>, reason: string): void {
    this.annotationsDropped += 1;
    if (this.annotationWarnings.length >= 10) return;
    const stage = record.stage_id;
    const stageStr = typeof stage === "string" ? stage : "unknown";
    const safe = reason === "hook_failed" || reason === "invalid_spec" || reason === "invalid_payload" ? reason : "invalid_payload";
    this.annotationWarnings.push(`${stageStr}:${safe}`);
  }

  private maybeEmitStageAnnotation(record: Record<string, unknown>, event: WorkflowEvent): void {
    const hook = this.config.onStageCompleted;
    if (!hook || this.finished) return;
    let spec: StageAnnotationSpec | null | undefined;
    try {
      spec = hook({
        stageId: record.stage_id as string,
        stageVisitId: record.stage_visit_id as string,
        sequence: event.sequence,
      });
    } catch {
      this.recordAnnotationWarning(record, "hook_failed");
      return;
    }
    if (!spec) return;
    try {
      if (typeof spec !== "object" || spec === null) {
        this.recordAnnotationWarning(record, "invalid_spec");
        return;
      }
      const { namespace, kind, payload } = spec as StageAnnotationSpec;
      if (typeof namespace !== "string" || typeof kind !== "string") {
        this.recordAnnotationWarning(record, "invalid_spec");
        return;
      }
      if (payload === undefined || payload === null || typeof payload !== "object") {
        this.recordAnnotationWarning(record, "invalid_payload");
        return;
      }
      // Force anchor to the triggering sequence; never trust hook anchor.
      const triggering = event.sequence;
      const anchor = typeof triggering === "number" && Number.isInteger(triggering) && triggering >= 1 ? triggering : undefined;
      const persisted = this.recordAnnotation(namespace, kind, payload, anchor, {
        stageId: record.stage_id as string,
        stageVisitId: record.stage_visit_id as string,
      });
      if (persisted === null) {
        this.recordAnnotationWarning(record, "invalid_payload");
      }
    } catch {
      this.recordAnnotationWarning(record, "invalid_payload");
      return;
    }
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
    this.currentStageId = stageId;
    this.visitToStage.set(visit, stageId);
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
    let callId: string;
    if (queue && queue.length > 0) callId = queue.shift() as string;
    else {
      this.modelCount += 1;
      callId = `m-${this.modelCount}`;
    }
    this.lastModelId.set(visit, callId);
    return callId;
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
    // The schema requires model_call_id on every model_retry. A retry can
    // legally arrive with no pending call (e.g. a tool-error retry emitted
    // after model_completed consumed the call id). Reuse that consumed id:
    // the retry announces the failure of the attempt it follows, which
    // already has vault request/response evidence, so semantic verification
    // stays complete. Synthesize a fresh id only when the visit has no
    // prior model call at all.
    let callId = this.peekModel(visit);
    if (callId === null) callId = this.lastModelId.get(visit) ?? null;
    if (callId === null) {
      this.modelCount += 1;
      callId = `m-${this.modelCount}`;
    }
    record.model_call_id = callId;
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
    if (this.vault_enabled) {
      this.openToolCalls.set(callId, {
        args: event.args,
        capability: event.capability,
        tool_name: event.toolName,
        stage_visit_id: visit,
      });
    }
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
      if (current !== null && typeof current === "object" && !Array.isArray(current) && part in (current as Record<string, unknown>)) {
        current = (current as Record<string, unknown>)[part];
      } else if (Array.isArray(current) && /^\d+$/.test(part) && Number(part) < (current as unknown[]).length) {
        current = (current as unknown[])[Number(part)];
      } else {
        return;
      }
    }
    const last = parts[parts.length - 1];
    if (current !== null && typeof current === "object" && !Array.isArray(current) && last in (current as Record<string, unknown>)) {
      (current as Record<string, unknown>)[last] = this.newMarker(reason, (current as Record<string, unknown>)[last]);
      if (!Array.isArray(record.redacted_fields)) record.redacted_fields = [];
      const fields = record.redacted_fields as string[];
      if (!fields.includes(pointer)) fields.push(pointer);
    } else if (Array.isArray(current) && /^\d+$/.test(last) && Number(last) < (current as unknown[]).length) {
      (current as unknown[])[Number(last)] = this.newMarker(reason, (current as unknown[])[Number(last)]);
      if (!Array.isArray(record.redacted_fields)) record.redacted_fields = [];
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
    const vaultEnabled = this.vault_enabled;
    const capture: Record<string, unknown> = vaultEnabled
      ? {
          profile: "replay",
          vault_present: true,
          publication_eligible: false,
          redaction_policy: REDACTION_POLICY,
          scanner: { status: "passed", ruleset: SCANNER_RULESET },
        }
      : {
          profile: "audit",
          vault_present: false,
          publication_eligible: false,
          redaction_policy: REDACTION_POLICY,
          scanner: { status: "passed", ruleset: SCANNER_RULESET },
        };
    const manifestObj: Record<string, unknown> = {
      format: TRACE_FORMAT,
      trace_id: this.config.traceId,
      created_at: (this.beginTime ?? this.config.clock()).toISOString(),
      status,
      capture,
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
      annotations_dropped: this.annotationsDropped,
      annotation_warnings: [...this.annotationWarnings],
    };
    const payloads: Record<string, Uint8Array> = {
      [MANIFEST_PATH]: textEncoder.encode(canonicalStringify(manifestObj)),
      [GRAPH_PATH]: textEncoder.encode(canonicalStringify(graphObj)),
      [EVENTS_PATH]: eventsBytes,
      [SUMMARY_PATH]: textEncoder.encode(canonicalStringify(summaryObj)),
    };
    if (vaultEnabled) {
      await this.sealVaultEntries(payloads, manifestObj);
    }
    const integrityEntries = await Promise.all(
      Object.entries(payloads)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(async ([path, data]) => ({
          path,
          media_type:
            path === VAULT_ENC_PATH
              ? "application/octet-stream"
              : path.endsWith(".ndjson")
                ? "application/x-ndjson"
                : "application/json",
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

  private manifestSnapshotForVault(): Record<string, unknown> {
    if (this.manifest === null) throw new TraceError("workflow manifest snapshot must be an object");
    const m = this.manifest;
    const guardToSnapshot = (g: unknown): Record<string, unknown> => {
      const guard = g as Record<string, unknown>;
      const kind = guard["kind"] as string;
      // Python dataclass includes all fields cond, left, ref, right, plus ref etc. Emit null for missing.
      // Mirror Python's dataclasses.asdict output: always include cond, left, ref, right as null when absent.
      if (kind === "always") {
        return { cond: null, kind: "always", left: null, ref: null, right: null };
      }
      if (kind === "has_value" || kind === "missing") {
        return { kind, ref: guard["ref"] ? _toJsonable(guard["ref"]) : null, cond: null, left: null, right: null };
      }
      if (kind === "eq") {
        return { kind, left: _toJsonable(guard["left"]), right: _toJsonable(guard["right"]), cond: null, ref: null };
      }
      if (kind === "if") {
        return { kind, cond: _toJsonable(guard["cond"]), left: null, ref: null, right: null };
      }
      return { cond: null, kind, left: null, ref: null, right: null };
    };
    const manifestDict: Record<string, unknown> = {
      workflow_id: m.workflowId,
      entry_stage_id: m.entryStageId,
      exit_stage_ids: [...m.exitStageIds].sort(),
      inputs: m.inputs.map((i) => {
        const rec = i as unknown as Record<string, unknown>;
        const name = (rec["id"] as string) ?? (rec["name"] as string) ?? "";
        return { name, type: rec["type"] };
      }),
      capabilities: [...m.capabilities].sort(),
      policies: m.policies.map((p) => ({
        id: p.id,
        kind: p.kind,
        trigger: { capability: p.trigger.capability, bind: Object.fromEntries([...p.trigger.bind]) },
        requires: [...p.requires].map((r) => ({ capability: r.capability, args: Object.fromEntries([...r.args].map(([k, v]) => [k, _toJsonable(v)])) })),
        condition: p.condition ? _toJsonable(p.condition) : null,
      })),
      stages: m.stages.map((s) => ({
        id: s.id,
        prompt: s.prompt,
        reads: s.reads.map((r) => ({ ref: _toJsonable(r.ref), optional: r.optional })),
        writes: s.writes.map((w) => ({ name: w.name, type: w.type, optional: w.optional })),
        requires: [...s.requires].sort(),
        transitions: s.transitions.map((t) => ({
          to: t.to,
          priority: t.priority,
          reason: t.reason,
          guard: guardToSnapshot(t.guard),
        })),
        execution: {
          kind: s.execution.kind,
          capability: s.execution.capability ?? null,
          args: s.execution.args ? Object.fromEntries([...s.execution.args].map(([k, v]) => [k, _toJsonable(v)])) : {},
        },
      })),
    };
    return {
      manifest: manifestDict,
      ir_sha256: this.config.provenance.irSha256,
      workflow_id: m.workflowId,
    };
  }

  private async sealVaultEntries(payloads: Record<string, Uint8Array>, manifestObj: Record<string, unknown>): Promise<void> {
    const captureCfg = this.config.vaultCapture;
    if (this.config.vaultPassphrase === null) throw new TraceError("trace profile 'replay' requires vaultPassphrase");
    if (captureCfg.includeIr) {
      const snapshot = this.manifestSnapshotForVault();
      this.appendVaultRecord("full_workflow_ir", snapshot);
    }
    // Validate shape
    for (const rec of this.vaultRecords) {
      const err = vaultRecordShapeError(rec);
      if (err !== null) throw new TraceError(err);
    }
    const lines: Uint8Array[] = [];
    for (const rec of this.vaultRecords) {
      lines.push(textEncoder.encode(canonicalStringify(rec) + "\n"));
    }
    const plaintext = (() => {
      const total = lines.reduce((s, b) => s + b.length, 0);
      const out = new Uint8Array(total);
      let off = 0;
      for (const b of lines) { out.set(b, off); off += b.length; }
      return out;
    })();
    if (plaintext.length > captureCfg.maxVaultBytes) {
      throw new TraceError(`vault plaintext exceeds maxVaultBytes (${plaintext.length} > ${captureCfg.maxVaultBytes})`);
    }
    // Belt-and-braces scan of vault plaintext records
    const problems: string[] = [];
    for (let idx = 0; idx < this.vaultRecords.length; idx++) {
      const rec = this.vaultRecords[idx] as Record<string, unknown>;
      for (const finding of scanStrings(rec, "", this.registry)) {
        if (vaultFindingExcused(rec, finding)) continue;
        problems.push(`vault:${idx + 1}:${finding.pointer} [${finding.rule}]`);
      }
    }
    if (problems.length > 0) {
      const detail = problems.slice(0, 10).join("; ");
      throw new TraceError(`trace scanner blocked vault finalization with ${problems.length} finding(s): ${detail}`);
    }
    const manifestBytes = payloads[MANIFEST_PATH]!;
    const eventsBytes = payloads[EVENTS_PATH]!;
    const graphBytes = payloads[GRAPH_PATH]!;
    const workflow = manifestObj["workflow"] as Record<string, unknown>;
    const irSha = (workflow["ir_sha256"] as string | null) ?? VAULT_NULL_IR_SHA256;
    const aadDict: Record<string, unknown> = {
      events_sha256: await sha256Hex(eventsBytes),
      format: VAULT_AAD_FORMAT,
      ir_sha256: irSha || VAULT_NULL_IR_SHA256,
      manifest_sha256: await sha256Hex(manifestBytes),
      trace_id: this.config.traceId,
      workflow_graph_sha256: await sha256Hex(graphBytes),
    };
    const aad = textEncoder.encode(canonicalStringify(aadDict));
    const { salt, nonce, sealed } = await encryptVaultRecords(plaintext, this.config.vaultPassphrase!, aad);
    const metaObj = vaultMetaObject({ salt, nonce, aadDict });
    payloads[VAULT_ENC_PATH] = sealed;
    payloads[VAULT_META_PATH] = textEncoder.encode(canonicalStringify(metaObj));
  }

  private finalScan(entries: Record<string, Uint8Array>): void {
    const problems = scanCleartextEntries(entries, this.registry);
    if (problems.length > 0) {
      const detail = problems.slice(0, 10).join("; ");
      throw new TraceError(
        `trace scanner blocked finalization with ${problems.length} finding(s): ${detail}`,
      );
    }
  }
}

/**
 * Scan cleartext entries for `secrets-v1` findings and unsafe integers.
 *
 * Returns location-only problem strings (`entry:pointer [rule]`) and never the
 * matched value. Ciphertext (`private/vault.enc`) is skipped: it is
 * pseudorandom and its plaintext was scanned before encryption. Entry names are
 * scanned too. An omitted registry is the correct posture for a transform that
 * has no capture-time secret values (publication relies on capture-time
 * redaction plus these detector rules).
 */
export function scanCleartextEntries(
  entries: Record<string, Uint8Array>,
  registry: SecretRegistry = new SecretRegistry(),
): string[] {
  const problems: string[] = [];
  for (const [path, data] of Object.entries(entries)) {
    if (path === VAULT_ENC_PATH) continue;
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
        for (const finding of scanStrings(value, "", registry)) {
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
      for (const finding of scanStrings(value, "", registry)) {
        problems.push(`${path}:${finding.pointer} [${finding.rule}]`);
      }
      if (hasUnsafeInt(value)) {
        problems.push(`${path} [unsafe_integer]`);
      }
    }
    if (scanStrings({ name: path }, "/name", registry).length > 0) {
      problems.push(`${path}: filename finding`);
    }
  }
  return problems;
}

export class NoOpTraceRecorder {
  /** Zero-cost recorder used when tracing is disabled. */
  readonly vault_enabled = false;
  readonly vaultEnabled = false;
  policyTape: Map<string, string[]> | Record<string, string[]> | null = null;
  consumeTapedPolicy(policyId: unknown): string | null {
    const tape: unknown = (this as unknown as { policyTape: unknown }).policyTape;
    if (tape === null || tape === undefined || typeof policyId !== "string") return null;
    let queue: string[] | undefined;
    if (tape instanceof Map) queue = (tape as Map<string, string[]>).get(policyId);
    else queue = (tape as Record<string, string[]>)[policyId];
    if (!queue || queue.length === 0) return null;
    return queue.shift()!;
  }
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
  recordModelRequest(_modelCallId: string, _request: unknown): void {}
  recordModelResponse(_modelCallId: string, _facts: { responseBytes?: number; toolCallCount?: number; response?: unknown } = {}): void {}
  recordRunInputs(_inputs: unknown): void {}
  recordPolicyEvaluation(_stageVisitId: unknown, _policyId: unknown, _bound: unknown, _outcome: string): void {}
  beginToolCall(_stageId = "", _stageVisitId?: string): string {
    return "";
  }
  recordToolResult(_toolCallId: string, _result: unknown, _args?: unknown): void {}
  recordToolError(_toolCallId: string, _exc: unknown): void {}
  recordRunError(_exc: unknown): void {}
  recordTransitionEvaluation(_stageVisitId: string, _candidates: readonly unknown[]): void {}
  recordAnnotation(
    _namespace: string,
    _kind: string,
    _payload?: unknown,
    _anchorSequence?: number,
    _opts?: { stageId?: string; stageVisitId?: string },
  ): null {
    return null;
  }
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

/** Deterministic ZIP assembly: sorted names, fixed epoch, DEFLATE level 6 (STORE for vault.enc). */
export function writeArchive(entries: Record<string, Uint8Array>): Uint8Array {
  const sorted: Record<string, Uint8Array | [Uint8Array, { level: number; mtime: Date }]> = {};
  for (const name of Object.keys(entries).sort()) {
    const data = entries[name]!;
    if (name === VAULT_ENC_PATH) {
      sorted[name] = [data, { level: 0, mtime: ZIP_EPOCH }];
    } else {
      sorted[name] = [data, { level: ZIP_DEFLATE_LEVEL, mtime: ZIP_EPOCH }];
    }
  }
  return zipSync(sorted as unknown as Record<string, Uint8Array>, { mtime: ZIP_EPOCH });
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
  const allowed = new Set([...AUDIT_ENTRY_PATHS, INTEGRITY_PATH, ...VAULT_ENTRY_PATHS]);
  for (const name of names) {
    if (!allowed.has(name)) throw new TraceError(`trace archive has unexpected entry: ${name}`);
    if (name.includes("\\") || name.startsWith("/") || name.split("/").some((s) => s === "" || s === "." || s === "..")) {
      throw new TraceError(`trace archive has unsafe entry name: ${name}`);
    }
  }
  let total = 0;
  for (const meta of metas) {
    if (meta.name === VAULT_ENC_PATH) {
      if (meta.method !== 0) throw new TraceError(`trace archive entry ${meta.name} must use STORE`);
    } else if (meta.method !== 8) {
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
    return { ok: false, contentIdentity: null, warnings: [], errors: [String(error)], integrity: "failed", structural: "failed", semantic: "not-evaluated", replayability: "none" };
  }
  const errors: string[] = [];
  const warnings: string[] = [];
  for (const required of [MANIFEST_PATH, GRAPH_PATH, EVENTS_PATH, INTEGRITY_PATH]) {
    if (!(required in entries)) errors.push(`missing required entry ${required}`);
  }
  if (errors.length > 0) return { ok: false, contentIdentity: null, warnings, errors, integrity: "failed", structural: "failed", semantic: "not-evaluated", replayability: "none" };
  let integrity: Record<string, unknown>;
  try {
    integrity = parseJsonStrict(textDecoder.decode(entries[INTEGRITY_PATH])) as Record<string, unknown>;
  } catch (error) {
    return { ok: false, contentIdentity: null, warnings: [], errors: [`integrity.json unparsable: ${String(error)}`], integrity: "failed", structural: "failed", semantic: "not-evaluated", replayability: "none" };
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
    return { ok: false, contentIdentity: null, warnings, errors: [...errors, `content identity failed: ${String(error)}`], integrity: "failed", structural: "failed", semantic: "not-evaluated", replayability: "none" };
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
      // Order-insensitive: the writer serializes counts_by_kind as canonical
      // JSON (sorted keys) while the recompute below observes first-seen
      // ledger order. A plain JSON.stringify comparison would warn on every
      // valid archive, so both sides go through canonical key ordering.
      if (canonicalStringify(summary.counts_by_kind) !== canonicalStringify(kinds)) {
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
        } else {
          const ns = (ann as Record<string, unknown>).namespace;
          const kd = (ann as Record<string, unknown>).kind;
          const pl = (ann as Record<string, unknown>).payload;
          if (typeof ns !== "string" || ns.length < 1 || ns.length > 128) {
            errors.push(`public/events.ndjson:${idx + 1} invalid annotation namespace`);
          } else if (typeof kd !== "string" || kd.length < 1 || kd.length > 128) {
            errors.push(`public/events.ndjson:${idx + 1} invalid annotation kind`);
          } else if (ns === ANNOTATION_NAMESPACE && kd === ANNOTATION_KIND) {
            try {
              validateAutoresearchPayload(pl);
            } catch (e) {
              errors.push(`public/events.ndjson:${idx + 1} invalid trial_finished payload: ${String(e)}`);
            }
          } else if (pl === null || typeof pl !== "object" || Array.isArray(pl) || !("$redacted" in (pl as Record<string, unknown>))) {
            errors.push(`public/events.ndjson:${idx + 1} unknown annotation payload must be a redaction marker`);
          }
        }
      }
      if (hasUnsafeInt(ev)) {
        errors.push(`public/events.ndjson:${idx + 1} contains unsafe integer`);
      }
    }
  } catch (error) {
    errors.push(`event validation failed: ${String(error)}`);
  }
  // -- Phase 4: capture/vault consistency (errors) ----------------------
  let vaultPresent = false;
  let captureProfile: unknown = null;
  if (manifest !== null && typeof manifest === "object" && !Array.isArray(manifest)) {
    const cap = (manifest as Record<string, unknown>)["capture"];
    if (cap !== null && typeof cap === "object" && !Array.isArray(cap)) {
      vaultPresent = (cap as Record<string, unknown>)["vault_present"] === true;
      captureProfile = (cap as Record<string, unknown>)["profile"];
    }
  }
  const hasVaultEnc = VAULT_ENC_PATH in entries;
  const hasVaultMeta = VAULT_META_PATH in entries;
  if (hasVaultEnc !== hasVaultMeta) {
    errors.push("vault entries must co-occur: private/vault.enc + private/vault.meta.json");
  }
  const hasVault = hasVaultEnc && hasVaultMeta;
  if (vaultPresent && !hasVault) errors.push("manifest capture declares vault_present but vault entries are missing");
  if (hasVault && !vaultPresent) errors.push("vault entries present but manifest capture has vault_present=false");
  if (captureProfile === "replay" && !vaultPresent) errors.push("replay profile requires vault_present=true");
  if (captureProfile === "publication" && hasVault) errors.push("publication profile forbids a vault");
  if (captureProfile !== "audit" && captureProfile !== "replay" && captureProfile !== "publication") {
    errors.push(`manifest capture has invalid profile ${JSON.stringify(captureProfile)}`);
  }
  // -- Phase 4: structural path-shape check (warnings) ----
  const structuralNotes: string[] = [];
  try {
    const g = graph as Record<string, unknown> | null;
    const nodes = g?.["nodes"];
    if (Array.isArray(nodes)) {
      const nodeIds = new Set<string>();
      for (const n of nodes as unknown[]) {
        if (n !== null && typeof n === "object" && !Array.isArray(n)) nodeIds.add((n as Record<string, unknown>)["id"] as string);
      }
      const edges = new Set<string>();
      const transList = (g as Record<string, unknown>)["transitions"];
      if (Array.isArray(transList)) {
        for (const t of transList as unknown[]) {
          if (t !== null && typeof t === "object" && !Array.isArray(t)) {
            const tm = t as Record<string, unknown>;
            edges.add(`${String(tm["from"])}->${String(tm["to"])}`);
          }
        }
      }
      const unknownStages = new Set<string>();
      const badEdges = new Set<string>();
      for (const line of eventLines) {
        let ev: unknown;
        try { ev = parseJsonStrict(line); } catch { continue; }
        if (ev === null || typeof ev !== "object" || Array.isArray(ev)) continue;
        const m = ev as Record<string, unknown>;
        const kind = m["kind"] as string;
        if (kind === "stage_started") {
          const sid = m["stage_id"] as string;
          if (typeof sid === "string" && !nodeIds.has(sid)) unknownStages.add(sid);
        }
        if (kind === "transition_selected") {
          const edge = `${String(m["stage_id"])}->${String(m["transition_to"])}`;
          if (!edges.has(edge)) badEdges.add(edge);
        }
      }
      for (const s of [...unknownStages].sort().slice(0, 10)) structuralNotes.push(`ledger references stage ${JSON.stringify(s)} absent from workflow graph`);
      if (unknownStages.size > 10) structuralNotes.push(`... and ${unknownStages.size - 10} more unknown stages`);
      for (const e of [...badEdges].sort().slice(0, 10)) structuralNotes.push(`ledger transition ${JSON.stringify(e)} absent from workflow graph`);
      if (badEdges.size > 10) structuralNotes.push(`... and ${badEdges.size - 10} more unknown transitions`);
    }
  } catch (e) {
    structuralNotes.push(`structural check skipped: ${String(e)}`);
  }
  warnings.push(...structuralNotes);
  // -- Phase 4: level summary -------------------------------------------
  const integrityMarkers = ["hash mismatch", "length mismatch", "content identity", "missing from integrity", "integrity index", "integrity.json", "integrity contains", "missing required entry", "unparsable"];
  const ledgerMarkers = ["events.ndjson", "workflow graph", "manifest"];
  const integrityFailed = errors.some((e) => integrityMarkers.some((m) => e.includes(m)));
  const ledgerFailed = errors.some((e) => ledgerMarkers.some((m) => e.includes(m)));
  const integrityLevel = integrityFailed ? "failed" : "passed";
  let structuralLevel: string;
  if (ledgerFailed) structuralLevel = "failed";
  else if (structuralNotes.length > 0) structuralLevel = "passed-with-warnings";
  else structuralLevel = "passed";
  const ok = errors.length === 0;
  let replayability: string;
  if (ok && hasVault) replayability = "taped-replay";
  else if (ok) replayability = "playback-only";
  else replayability = "none";
  return {
    ok,
    contentIdentity: ok ? (contentIdentity as string) : null,
    warnings,
    errors,
    integrity: integrityLevel,
    structural: structuralLevel,
    semantic: "not-evaluated",
    replayability,
  };
}

export function checkVaultMeta(meta: unknown): Record<string, unknown> {
  if (meta === null || typeof meta !== "object" || Array.isArray(meta)) throw new TraceError("vault metadata must be an object");
  const d = meta as Record<string, unknown>;
  if (d["format"] !== VAULT_META_FORMAT) throw new TraceError("vault metadata format mismatch");
  if (d["codec"] !== VAULT_CODEC) throw new TraceError("vault uses an unsupported codec");
  const passphrase = d["passphrase"];
  if (passphrase === null || typeof passphrase !== "object" || Array.isArray(passphrase)) throw new TraceError("vault metadata passphrase descriptor invalid");
  const pp = passphrase as Record<string, unknown>;
  if (pp["encoding"] !== "UTF-8" || pp["normalization"] !== "NFC") throw new TraceError("vault metadata passphrase descriptor invalid");
  const kdf = d["kdf"];
  if (kdf === null || typeof kdf !== "object" || Array.isArray(kdf)) throw new TraceError("vault uses an unsupported KDF");
  const kd = kdf as Record<string, unknown>;
  if (kd["name"] !== VAULT_KDF_NAME || kd["iterations"] !== VAULT_KDF_ITERATIONS || kd["derived_key_bits"] !== VAULT_DERIVED_KEY_BITS) throw new TraceError("vault uses an unsupported KDF");
  const cipher = d["cipher"];
  if (cipher === null || typeof cipher !== "object" || Array.isArray(cipher)) throw new TraceError("vault uses an unsupported cipher");
  const cd = cipher as Record<string, unknown>;
  if (cd["name"] !== "AES-256-GCM" || cd["tag_length_bits"] !== VAULT_TAG_BITS || cd["tag_placement"] !== "ciphertext_suffix") throw new TraceError("vault uses an unsupported cipher");
  const plaintext = d["plaintext"];
  if (plaintext === null || typeof plaintext !== "object" || Array.isArray(plaintext)) throw new TraceError("vault metadata plaintext descriptor invalid");
  const pd = plaintext as Record<string, unknown>;
  if (pd["media_type"] !== VAULT_PLAINTEXT_MEDIA_TYPE || pd["encoding"] !== "UTF-8" || pd["compression"] !== "none") throw new TraceError("vault metadata plaintext descriptor invalid");
  const aad = d["aad"];
  if (aad === null || typeof aad !== "object" || Array.isArray(aad)) throw new TraceError("vault metadata AAD descriptor invalid");
  const ad = aad as Record<string, unknown>;
  if (ad["format"] !== VAULT_AAD_FORMAT) throw new TraceError("vault metadata AAD descriptor invalid");
  for (const n of ["trace_id", "ir_sha256", "manifest_sha256", "events_sha256", "workflow_graph_sha256"]) {
    if (!(n in ad)) throw new TraceError(`vault metadata AAD missing ${JSON.stringify(n)}`);
  }
  return d;
}

async function expectedVaultAad(entries: Record<string, Uint8Array>, manifest: Record<string, unknown>): Promise<{ aad: Uint8Array; aadDict: Record<string, unknown> }> {
  const workflow = (manifest["workflow"] as Record<string, unknown>) ?? {};
  const aadDict: Record<string, unknown> = {
    events_sha256: await sha256Hex(entries[EVENTS_PATH]!),
    format: VAULT_AAD_FORMAT,
    ir_sha256: (workflow["ir_sha256"] as string) || VAULT_NULL_IR_SHA256,
    manifest_sha256: await sha256Hex(entries[MANIFEST_PATH]!),
    trace_id: manifest["trace_id"],
    workflow_graph_sha256: await sha256Hex(entries[GRAPH_PATH]!),
  };
  return { aad: textEncoder.encode(canonicalStringify(aadDict)), aadDict };
}

function checkVaultEvidence(entries: Record<string, Uint8Array>, records: Record<string, unknown>[]): string[] {
  const problems: string[] = [];
  const modelIds = new Set<string>();
  const toolIds = new Set<string>();
  const transitionVisits = new Set<string>();
  for (const rec of records) {
    const rtype = rec["record_type"] as string;
    if (rtype === "model_request" || rtype === "model_response") {
      const mid = rec["model_call_id"] as string;
      if (typeof mid === "string") modelIds.add(mid);
    } else if (rtype === "tool_result") {
      const tid = rec["tool_call_id"] as string;
      if (typeof tid === "string") toolIds.add(tid);
    } else if (rtype === "transition_evaluation") {
      const visit = rec["stage_visit_id"] as string;
      if (typeof visit === "string") transitionVisits.add(visit);
    }
  }
  const lines = textDecoder.decode(entries[EVENTS_PATH]!).split("\n").filter((l) => l.trim() !== "");
  for (const line of lines) {
    let ev: unknown;
    try { ev = parseJsonStrict(line); } catch { continue; }
    if (ev === null || typeof ev !== "object" || Array.isArray(ev)) continue;
    const m = ev as Record<string, unknown>;
    const kind = m["kind"] as string;
    if (kind === "model_completed" || kind === "model_retry") {
      const mid = m["model_call_id"] as string;
      if (typeof mid === "string" && !modelIds.has(mid)) problems.push(`vault missing model evidence for ${mid}`);
    } else if (kind === "tool_call_completed" || kind === "tool_call_failed") {
      const tid = m["tool_call_id"] as string;
      if (typeof tid === "string" && !toolIds.has(tid)) problems.push(`vault missing tool evidence for ${tid}`);
    } else if (kind === "transition_selected") {
      const visit = m["stage_visit_id"] as string;
      if (typeof visit === "string" && !transitionVisits.has(visit)) problems.push(`vault missing transition evidence for visit ${visit}`);
    }
  }
  return problems.slice(0, 50);
}

export async function unlockArchive(data: Uint8Array, passphrase: string | Uint8Array): Promise<{ records: Record<string, unknown>[]; report: VerificationReport }> {
  const report = await verifyArchive(data);
  if (!report.ok) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, "archive verification failed"] } };
  }
  if (report.replayability !== "taped-replay") {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, "archive has no replay vault"] } };
  }
  let entries: Record<string, Uint8Array>;
  try {
    entries = readArchiveEntries(data);
  } catch (e) {
    const msg = String(e);
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, msg] } };
  }
  let metaRaw: unknown;
  let manifestRaw: unknown;
  try {
    metaRaw = parseJsonStrict(textDecoder.decode(entries[VAULT_META_PATH]!));
    manifestRaw = parseJsonStrict(textDecoder.decode(entries[MANIFEST_PATH]!));
  } catch (e) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, `vault metadata invalid: ${String(e)}`] } };
  }
  let meta: Record<string, unknown>;
  try {
    meta = checkVaultMeta(metaRaw);
  } catch (e) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, `vault metadata invalid: ${String(e)}`] } };
  }
  if (manifestRaw === null || typeof manifestRaw !== "object" || Array.isArray(manifestRaw)) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, "vault metadata invalid: manifest must be an object"] } };
  }
  const manifest = manifestRaw as Record<string, unknown>;
  const kdf = (meta["kdf"] as Record<string, unknown>);
  const cipher = (meta["cipher"] as Record<string, unknown>);
  let salt: Uint8Array;
  let nonce: Uint8Array;
  try {
    salt = b64urlDecode(kdf["salt_base64url"] as string, "salt", VAULT_SALT_BYTES);
    nonce = b64urlDecode(cipher["nonce_base64url"] as string, "nonce", VAULT_NONCE_BYTES);
  } catch (e) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, `vault metadata invalid: ${String(e)}`] } };
  }
  let pwBytes: Uint8Array | null;
  try {
    pwBytes = normalizePassphrase(passphrase as string | Uint8Array);
  } catch {
    pwBytes = null;
  }
  if (pwBytes === null) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, "vault unlock failed"] } };
  }
  const { aad: expectedAad } = await expectedVaultAad(entries, manifest);
  const storedAad = meta["aad"] as Record<string, unknown>;
  let aadOk = true;
  for (const [name, digestPromise] of [
    ["manifest_sha256", sha256Hex(entries[MANIFEST_PATH]!)],
    ["events_sha256", sha256Hex(entries[EVENTS_PATH]!)],
    ["workflow_graph_sha256", sha256Hex(entries[GRAPH_PATH]!)],
  ] as const) {
    const digest = await digestPromise;
    if ((storedAad as Record<string, unknown>)[name] !== digest) aadOk = false;
  }
  if (!aadOk || (storedAad as Record<string, unknown>)["trace_id"] !== manifest["trace_id"]) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, "vault unlock failed"] } };
  }
  let plaintext: Uint8Array;
  try {
    plaintext = await decryptVaultRecords(entries[VAULT_ENC_PATH]!, pwBytes, expectedAad, { salt, nonce });
  } catch (e) {
    const msg = e instanceof TraceError ? e.message : "vault unlock failed";
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, msg] } };
  }
  let rawLines = plaintext.length === 0 ? [] : textDecoder.decode(plaintext).split("\n").filter((l) => l.trim() !== "");
  let parsed: unknown[] = [];
  try {
    parsed = rawLines.map((line) => parseJsonStrict(line));
  } catch (e) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, `vault invalid: ${String(e)}`] } };
  }
  if (parsed.length > LIMIT_EVENT_COUNT) {
    return { records: [], report: { ...report, ok: false, semantic: "failed", errors: [...report.errors, "vault invalid: record count exceeds budget"] } };
  }
  const records: Record<string, unknown>[] = [];
  for (let idx = 0; idx < parsed.length; idx++) {
    const rec = parsed[idx];
    if (rec === null || typeof rec !== "object" || Array.isArray(rec)) {
      return { records: [], report: { ...report, semantic: "failed", errors: [...report.errors, `vault invalid: record ${idx + 1} must be an object`] } };
    }
    const err = vaultRecordShapeError(rec);
    if (err !== null) {
      return { records: [], report: { ...report, semantic: "failed", errors: [...report.errors, `vault invalid: ${err}`] } };
    }
    records.push(rec as Record<string, unknown>);
  }
  const semanticErrors = checkVaultEvidence(entries, records);
  const semantic = semanticErrors.length === 0 ? "passed" : "failed";
  return {
    records,
    report: {
      ...report,
      semantic,
      warnings: report.warnings,
      errors: [...report.errors, ...semanticErrors],
      ok: report.ok && semanticErrors.length === 0,
    },
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
