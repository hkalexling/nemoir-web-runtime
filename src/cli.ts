/**
 * `nemotrace-js` verifier CLI: integrity, structural, semantic, and replay checks.
 *
 * Usage:
 *
 * ```text
 * nemotrace-js verify <archive> [--unlock SRC | --replay SRC]
 * nemotrace-js scan-publication <archive> [--allow-tool-name NAME]... [--keep-relative-paths]
 * nemotrace-js attest-publication --report PATH --reviewer NAME --license ID --consent TEXT
 * nemotrace-js prepare-publication <archive> <destination> --attest PATH
 * ```
 *
 * `SRC` is `env:VAR` | `file:PATH` | `prompt`. Prints the same stable
 * line-oriented report as the Python `nemotrace` CLI (see
 * `docs/trace/schema/test-vectors/cli/` for the shared golden outputs) and
 * returns `0` when the requested level passed, `1` when it failed, and `2`
 * for usage errors. Passphrase values, vault plaintext, and stack traces are
 * never printed.
 */

import { readFileSync, statSync, writeFileSync } from "node:fs";
import { basename } from "node:path";

import { parseJsonStrict } from "./canonical.js";
import {
  PublicationError,
  attestationDocument,
  attestationFromDict,
  attestationFromReport,
  preparePublication,
  publicationReport,
  publicationReportPath,
  scanPublication,
  serializeDocument,
  type PublicationAttestation,
  type PublicationProjection,
} from "./publication.js";
import { replayTrace } from "./replay.js";
import type { ReplayReport } from "./replay.js";
import { TraceError, readArchiveEntries, unlockArchive, verifyArchive } from "./trace.js";
import type { VerificationReport } from "./trace.js";

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_USAGE = 2;
const MAX_DIAGNOSTICS = 10;
const MISSING = "-";

const USAGE = [
  "usage: nemotrace-js verify <archive> [--unlock SRC | --replay SRC]",
  "       nemotrace-js scan-publication <archive> [--allow-tool-name NAME]... [--keep-relative-paths]",
  "       nemotrace-js attest-publication --report PATH --reviewer NAME --license ID --consent TEXT",
  "       nemotrace-js prepare-publication <archive> <destination> --attest PATH",
].join("\n");

export interface CliIO {
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
  readonly env: Record<string, string | undefined>;
  readonly readTextFile: (path: string) => string;
  readonly writeTextFile: (path: string, text: string) => void;
  readonly readBytes: (path: string) => Uint8Array;
  readonly writeBytes: (path: string, data: Uint8Array) => void;
  readonly promptPassphrase: () => Promise<string | null>;
  readonly now: () => string;
}

interface ParsedVerify {
  readonly archive: string;
  readonly source: string | null;
  readonly replay: boolean;
}

function parseVerifyArgs(argv: readonly string[], io: CliIO): ParsedVerify | null {
  const [, ...rest] = argv;
  let archive: string | null = null;
  let unlock: string | null = null;
  let replay: string | null = null;
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    const [flag, inline] = token.includes("=") ? [token.slice(0, token.indexOf("=")), token.slice(token.indexOf("=") + 1)] : [token, null];
    if (flag === "--unlock" || flag === "--replay") {
      let value = inline;
      if (value === null) {
        index += 1;
        value = rest[index] ?? null;
      }
      if (value === null || value === "") {
        io.err(USAGE);
        io.err(`error: ${flag} requires a passphrase source (env:VAR | file:PATH | prompt)`);
        return null;
      }
      if (flag === "--unlock") unlock = value;
      else replay = value;
    } else if (token.startsWith("--")) {
      io.err(USAGE);
      io.err(`error: unknown option: ${token}`);
      return null;
    } else if (archive === null) {
      archive = token;
    } else {
      io.err(USAGE);
      io.err(`error: unexpected argument: ${token}`);
      return null;
    }
  }
  if (archive === null) {
    io.err(USAGE);
    io.err("error: the following arguments are required: archive");
    return null;
  }
  if (unlock !== null && replay !== null) {
    io.err(USAGE);
    io.err("error: --unlock and --replay are mutually exclusive");
    return null;
  }
  return { archive, source: replay ?? unlock, replay: replay !== null };
}

async function readHiddenPassphrase(promptText: string): Promise<string | null> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const chunk of stdin) chunks.push(Buffer.from(chunk as Buffer));
    return Buffer.concat(chunks).toString("utf8").split("\n")[0]?.trim() ?? "";
  }
  process.stderr.write(promptText);
  stdin.setRawMode(true);
  stdin.resume();
  return await new Promise<string | null>((resolvePromise) => {
    let buffer = "";
    const cleanup = (): void => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off("data", onData);
    };
    const onData = (chunk: Buffer | string): void => {
      for (const character of chunk.toString("utf8")) {
        if (character === "\r" || character === "\n") {
          cleanup();
          process.stderr.write("\n");
          resolvePromise(buffer);
          return;
        }
        if (character === "\u0003") {
          cleanup();
          process.stderr.write("\n");
          resolvePromise(null);
          return;
        }
        if (character === "\u007f" || character === "\b") {
          buffer = buffer.slice(0, -1);
          continue;
        }
        buffer += character;
      }
    };
    stdin.on("data", onData);
  });
}

function defaultIO(): CliIO {
  return {
    out: (line) => {
      process.stdout.write(`${line}\n`);
    },
    err: (line) => {
      process.stderr.write(`${line}\n`);
    },
    env: process.env,
    readTextFile: (path) => readFileSync(path, "utf8"),
    writeTextFile: (path, text) => writeFileSync(path, text),
    readBytes: (path) => new Uint8Array(readFileSync(path)),
    writeBytes: (path, data) => writeFileSync(path, data),
    promptPassphrase: () => readHiddenPassphrase("vault passphrase: "),
    now: () => new Date().toISOString(),
  };
}

async function resolvePassphrase(spec: string, io: CliIO): Promise<string> {
  if (spec === "prompt") {
    const value = await io.promptPassphrase();
    if (value === null) throw new Error("passphrase prompt was cancelled");
    if (value === "") throw new Error("passphrase prompt supplied an empty passphrase");
    return value;
  }
  if (spec.startsWith("env:")) {
    const variable = spec.slice("env:".length);
    if (variable === "") throw new Error("env: requires a variable name (env:VAR)");
    const value = io.env[variable];
    if (value === undefined || value === "") {
      throw new Error(`${spec}: environment variable is missing or empty`);
    }
    return value;
  }
  if (spec.startsWith("file:")) {
    const raw = spec.slice("file:".length);
    if (raw === "") throw new Error("file: requires a path (file:PATH)");
    let value: string;
    try {
      value = io.readTextFile(raw).trim();
    } catch {
      throw new Error(`${spec}: cannot read file`);
    }
    if (value === "") throw new Error(`${spec}: file is empty`);
    return value;
  }
  throw new Error(`${JSON.stringify(spec)}: expected env:VAR | file:PATH | prompt`);
}

function dictField(node: unknown, key: string): Record<string, unknown> {
  if (node === null || typeof node !== "object" || Array.isArray(node)) return {};
  const value = (node as Record<string, unknown>)[key];
  if (value === null || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function strField(node: unknown, key: string): string {
  if (node === null || typeof node !== "object" || Array.isArray(node)) return MISSING;
  const value = (node as Record<string, unknown>)[key];
  return typeof value === "string" && value !== "" ? value : MISSING;
}

function readManifest(entries: Record<string, Uint8Array> | null): Record<string, unknown> {
  if (entries === null) return {};
  const raw = entries["manifest.json"];
  if (raw === undefined) return {};
  try {
    const parsed: unknown = parseJsonStrict(new TextDecoder().decode(raw));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return parsed as Record<string, unknown>;
  } catch {
    return {};
  }
}

function readEntries(bytes: Uint8Array): Record<string, Uint8Array> | null {
  try {
    return readArchiveEntries(bytes);
  } catch {
    return null;
  }
}

function singleLine(value: string): string {
  return value.split(/\s+/).join(" ").trim();
}

function diagnosticLines(label: string, values: readonly string[]): string[] {
  const items = values.map((value) => singleLine(String(value)));
  const lines = items.slice(0, MAX_DIAGNOSTICS).map((item) => `${label}: ${item}`);
  if (items.length > MAX_DIAGNOSTICS) lines.push(`${label}_more: ${items.length - MAX_DIAGNOSTICS}`);
  return lines;
}

function fallbackReport(): VerificationReport {
  return {
    ok: false,
    contentIdentity: null,
    warnings: [],
    errors: ["verification could not run"],
    integrity: "failed",
    structural: "failed",
    semantic: "failed",
    replayability: "none",
  };
}

async function unlockReport(bytes: Uint8Array, passphrase: string): Promise<VerificationReport> {
  try {
    return (await unlockArchive(bytes, passphrase)).report;
  } catch {
    try {
      return await verifyArchive(bytes);
    } catch {
      return fallbackReport();
    }
  }
}

function verifyLines(
  archive: string,
  manifest: Record<string, unknown>,
  report: VerificationReport,
  replayRequested: boolean,
  replayReport: ReplayReport | null,
  replayFailed: boolean,
): { readonly lines: string[]; readonly resultOk: boolean } {
  const workflow = dictField(manifest, "workflow");
  const capture = dictField(manifest, "capture");
  const errors = [...report.errors];
  if (replayFailed) errors.push("taped replay could not run");
  const replayState = replayFailed ? "error" : replayReport?.matched ? "matched" : "diverged";
  const lines = [
    `archive: ${basename(archive)}`,
    `format: ${strField(manifest, "format")}`,
    `trace_id: ${strField(manifest, "trace_id")}`,
    `workflow: ${strField(workflow, "id")}`,
    `profile: ${strField(capture, "profile")}`,
    `status: ${strField(manifest, "status")}`,
    `content_identity: ${report.contentIdentity ?? MISSING}`,
    `integrity: ${report.integrity}`,
    `structural: ${report.structural}`,
    `semantic: ${report.semantic}`,
    `replayability: ${report.replayability}`,
    `warnings: ${report.warnings.length}`,
    `errors: ${errors.length}`,
  ];
  if (replayRequested) {
    lines.push(
      `replay: ${replayState}`,
      `replay_status: ${replayReport?.replayedStatus ?? "unknown"}`,
      `replay_steps: ${replayReport?.steps ?? 0}`,
      `divergences: ${replayReport?.divergences.length ?? 0}`,
    );
  }
  lines.push(...diagnosticLines("warning", report.warnings));
  lines.push(...diagnosticLines("error", errors));
  if (replayRequested && replayReport !== null) {
    lines.push(...diagnosticLines("divergence", replayReport.divergences));
  }
  const resultOk = replayRequested ? replayReport !== null && replayReport.matched : report.ok;
  lines.push(`result: ${resultOk ? "ok" : "failed"}`);
  return { lines, resultOk };
}

function requireFile(path: string, what: string, io: CliIO): string | null {
  let exists = false;
  let isFile = false;
  try {
    isFile = statSync(path).isFile();
    exists = true;
  } catch {
    exists = false;
  }
  if (!exists) {
    io.err(`error: ${what} not found: ${path}`);
    return `${what} not found`;
  }
  if (!isFile) {
    io.err(`error: ${what} is not a file: ${path}`);
    return `${what} is not a file`;
  }
  return null;
}

interface ScanArgs {
  readonly archive: string;
  readonly allowToolNames: string[];
  readonly keepRelativePaths: boolean;
  readonly report: string | null;
}

function parseScanArgs(rest: readonly string[], io: CliIO): ScanArgs | null {
  let archive: string | null = null;
  const allowToolNames: string[] = [];
  let keepRelativePaths = false;
  let report: string | null = null;
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    const [flag, inline] = token.includes("=")
      ? [token.slice(0, token.indexOf("=")), token.slice(token.indexOf("=") + 1)]
      : [token, null];
    if (flag === "--allow-tool-name") {
      let value = inline;
      if (value === null) {
        index += 1;
        value = rest[index] ?? null;
      }
      if (value === null || value === "") {
        io.err(`error: --allow-tool-name requires a tool name`);
        return null;
      }
      allowToolNames.push(value);
    } else if (flag === "--keep-relative-paths") {
      keepRelativePaths = true;
    } else if (flag === "--report") {
      let value = inline;
      if (value === null) {
        index += 1;
        value = rest[index] ?? null;
      }
      if (value === null || value === "") {
        io.err("error: --report requires a path");
        return null;
      }
      report = value;
    } else if (token.startsWith("--")) {
      io.err(`error: unknown option: ${token}`);
      return null;
    } else if (archive === null) {
      archive = token;
    } else {
      io.err(`error: unexpected argument: ${token}`);
      return null;
    }
  }
  if (archive === null) {
    io.err("error: the following arguments are required: archive");
    return null;
  }
  return { archive, allowToolNames, keepRelativePaths, report };
}

function scanLines(
  projection: PublicationProjection,
  reportName: string | null,
): { readonly lines: string[]; readonly ok: boolean } {
  const stats = projection.stats;
  const ok = projection.findings.length === 0;
  const lines = [
    `archive: ${projection.source.archive}`,
    `trace_id: ${projection.source.trace_id}`,
    `content_identity: ${projection.source.content_identity || MISSING}`,
    `profile: ${projection.source.profile}`,
    `status: ${projection.source.status}`,
    `events: ${stats.event_count}`,
    `stage_visits: ${stats.stage_visit_count}`,
    `tool_names_removed: ${stats.tool_names_removed}`,
    `tool_names_retained: ${stats.tool_names_retained}`,
    `paths_opaque: ${stats.paths_opaque}`,
    `projection_sha256: ${projection.projection_sha256}`,
    `predicted_content_identity: ${projection.content_identity}`,
    `scan: ${ok ? "passed" : "failed"}`,
    `findings: ${projection.findings.length}`,
    ...diagnosticLines("finding", projection.findings),
    `report: ${reportName ?? MISSING}`,
    `result: ${ok ? "ok" : "failed"}`,
  ];
  return { lines, ok };
}

async function scanPublicationCommand(rest: readonly string[], io: CliIO): Promise<number> {
  const args = parseScanArgs(rest, io);
  if (args === null) {
    io.err(USAGE);
    return EXIT_USAGE;
  }
  if (requireFile(args.archive, "archive", io) !== null) return EXIT_USAGE;
  const reportPath = args.report ?? publicationReportPath(args.archive);
  let projection: PublicationProjection;
  try {
    projection = await scanPublication(
      args.archive,
      io.readBytes(args.archive),
      {
        allow_tool_names: args.allowToolNames,
        keep_relative_paths: args.keepRelativePaths,
      },
      basename(args.archive),
    );
  } catch (error) {
    io.err(`error: ${errorMessage(error)}`);
    return EXIT_FAILED;
  }
  try {
    io.writeTextFile(
      reportPath,
      new TextDecoder().decode(
        serializeDocument(publicationReport(projection, false, null)),
      ),
    );
  } catch (error) {
    io.err(`error: cannot write report: ${errorMessage(error)}`);
    return EXIT_FAILED;
  }
  const { lines, ok } = scanLines(projection, basename(reportPath));
  for (const line of lines) io.out(line);
  return ok ? EXIT_OK : EXIT_FAILED;
}

interface AttestArgs {
  readonly report: string;
  readonly reviewer: string;
  readonly license: string;
  readonly consent: string;
  readonly out: string | null;
  readonly reviewedAt: string | null;
}

function parseAttestArgs(rest: readonly string[], io: CliIO): AttestArgs | null {
  const values: Record<string, string> = {};
  const flags = new Set([
    "--report",
    "--reviewer",
    "--license",
    "--consent",
    "--out",
    "--reviewed-at",
  ]);
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    const [flag, inline] = token.includes("=")
      ? [token.slice(0, token.indexOf("=")), token.slice(token.indexOf("=") + 1)]
      : [token, null];
    if (!flags.has(flag)) {
      io.err(`error: unknown option: ${token}`);
      return null;
    }
    let value = inline;
    if (value === null) {
      index += 1;
      value = rest[index] ?? null;
    }
    if (value === null || value === "") {
      io.err(`error: ${flag} requires a value`);
      return null;
    }
    values[flag] = value;
  }
  for (const required of ["--report", "--reviewer", "--license", "--consent"]) {
    if (!(required in values)) {
      io.err(`error: the following arguments are required: ${required}`);
      return null;
    }
  }
  return {
    report: values["--report"]!,
    reviewer: values["--reviewer"]!,
    license: values["--license"]!,
    consent: values["--consent"]!,
    out: values["--out"] ?? null,
    reviewedAt: values["--reviewed-at"] ?? null,
  };
}

async function attestPublicationCommand(rest: readonly string[], io: CliIO): Promise<number> {
  const args = parseAttestArgs(rest, io);
  if (args === null) {
    io.err(USAGE);
    return EXIT_USAGE;
  }
  if (requireFile(args.report, "report", io) !== null) return EXIT_USAGE;
  let attestation: PublicationAttestation;
  try {
    const parsed: unknown = JSON.parse(io.readTextFile(args.report));
    attestation = attestationFromReport(parsed, {
      reviewer: args.reviewer,
      license: args.license,
      consent: args.consent,
      ...(args.reviewedAt === null ? { reviewed_at: io.now() } : { reviewed_at: args.reviewedAt }),
    });
  } catch (error) {
    io.err(`error: ${errorMessage(error)}`);
    return EXIT_FAILED;
  }
  const outPath = args.out ?? `${args.report}.attestation.json`;
  try {
    io.writeTextFile(
      outPath,
      new TextDecoder().decode(serializeDocument(attestationDocument(attestation))),
    );
  } catch (error) {
    io.err(`error: cannot write attestation: ${errorMessage(error)}`);
    return EXIT_FAILED;
  }
  const lines = [
    `report: ${basename(args.report)}`,
    `projection_sha256: ${attestation.projection_sha256}`,
    `source_trace_id: ${attestation.source_trace_id}`,
    `reviewer: ${attestation.reviewer}`,
    `license: ${attestation.license}`,
    `reviewed_at: ${attestation.reviewed_at}`,
    `attestation: ${basename(outPath)}`,
    "result: ok",
  ];
  for (const line of lines) io.out(line);
  return EXIT_OK;
}

interface PrepareArgs {
  readonly archive: string;
  readonly destination: string;
  readonly attest: string;
  readonly report: string | null;
}

function parsePrepareArgs(rest: readonly string[], io: CliIO): PrepareArgs | null {
  let archive: string | null = null;
  let destination: string | null = null;
  let attest: string | null = null;
  let report: string | null = null;
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    const [flag, inline] = token.includes("=")
      ? [token.slice(0, token.indexOf("=")), token.slice(token.indexOf("=") + 1)]
      : [token, null];
    if (flag === "--attest" || flag === "--report") {
      let value = inline;
      if (value === null) {
        index += 1;
        value = rest[index] ?? null;
      }
      if (value === null || value === "") {
        io.err(`error: ${flag} requires a path`);
        return null;
      }
      if (flag === "--attest") attest = value;
      else report = value;
    } else if (token.startsWith("--")) {
      io.err(`error: unknown option: ${token}`);
      return null;
    } else if (archive === null) {
      archive = token;
    } else if (destination === null) {
      destination = token;
    } else {
      io.err(`error: unexpected argument: ${token}`);
      return null;
    }
  }
  if (archive === null || destination === null) {
    io.err("error: the following arguments are required: archive, destination");
    return null;
  }
  if (attest === null) {
    io.err("error: the following arguments are required: --attest");
    return null;
  }
  return { archive, destination, attest, report };
}

async function preparePublicationCommand(rest: readonly string[], io: CliIO): Promise<number> {
  const args = parsePrepareArgs(rest, io);
  if (args === null) {
    io.err(USAGE);
    return EXIT_USAGE;
  }
  if (requireFile(args.archive, "archive", io) !== null) return EXIT_USAGE;
  let attestation: PublicationAttestation;
  try {
    attestation = attestationFromDict(JSON.parse(io.readTextFile(args.attest)));
  } catch (error) {
    io.err(`error: ${errorMessage(error)}`);
    return EXIT_FAILED;
  }
  const reportPath = args.report ?? publicationReportPath(args.destination);
  let bytes: Uint8Array;
  let projection: PublicationProjection;
  let result: Awaited<ReturnType<typeof preparePublication>>["result"];
  try {
    const prepared = await preparePublication(
      args.archive,
      io.readBytes(args.archive),
      args.destination,
      attestation,
    );
    bytes = prepared.bytes;
    projection = prepared.projection;
    result = prepared.result;
  } catch (error) {
    io.err(`error: ${errorMessage(error)}`);
    return EXIT_FAILED;
  }
  try {
    io.writeBytes(args.destination, bytes);
    io.writeTextFile(
      reportPath,
      new TextDecoder().decode(
        serializeDocument(publicationReport(projection, true, attestation)),
      ),
    );
  } catch (error) {
    io.err(`error: cannot write publication: ${errorMessage(error)}`);
    return EXIT_FAILED;
  }
  const lines = [
    `archive: ${basename(args.archive)}`,
    `publication: ${basename(args.destination)}`,
    `trace_id: ${result.trace_id}`,
    `projection_sha256: ${result.projection_sha256}`,
    "scan: passed",
    "attested: true",
    `reviewer: ${attestation.reviewer}`,
    `license: ${attestation.license}`,
    `events: ${result.stats.event_count}`,
    `content_identity: ${result.content_identity}`,
    `report: ${basename(reportPath)}`,
    "result: ok",
  ];
  for (const line of lines) io.out(line);
  return EXIT_OK;
}

function errorMessage(error: unknown): string {
  if (error instanceof PublicationError || error instanceof TraceError || error instanceof Error) {
    return error.message;
  }
  return String(error);
}

export async function main(argv: readonly string[], ioOverride: Partial<CliIO> = {}): Promise<number> {
  const io: CliIO = { ...defaultIO(), ...ioOverride };
  const command = argv[0];
  const rest = argv.slice(1);
  if (command === "scan-publication") return scanPublicationCommand(rest, io);
  if (command === "attest-publication") return attestPublicationCommand(rest, io);
  if (command === "prepare-publication") return preparePublicationCommand(rest, io);
  if (command !== "verify") {
    io.err(USAGE);
    io.err("error: expected one of 'verify', 'scan-publication', 'attest-publication', 'prepare-publication'");
    return EXIT_USAGE;
  }
  const parsed = parseVerifyArgs(argv, io);
  if (parsed === null) return EXIT_USAGE;

  let exists = false;
  let isFile = false;
  try {
    isFile = statSync(parsed.archive).isFile();
    exists = true;
  } catch {
    exists = false;
  }
  if (!exists) {
    io.err(`error: archive not found: ${parsed.archive}`);
    return EXIT_USAGE;
  }
  if (!isFile) {
    io.err(`error: archive is not a file: ${parsed.archive}`);
    return EXIT_USAGE;
  }
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(readFileSync(parsed.archive));
  } catch {
    io.err(`error: archive could not be read: ${parsed.archive}`);
    return EXIT_USAGE;
  }
  const manifest = readManifest(readEntries(bytes));

  let passphrase: string | null = null;
  if (parsed.source !== null) {
    try {
      passphrase = await resolvePassphrase(parsed.source, io);
    } catch (error) {
      io.err(`error: ${error instanceof Error ? error.message : String(error)}`);
      return EXIT_USAGE;
    }
  }

  let report: VerificationReport;
  let replayReport: ReplayReport | null = null;
  let replayFailed = false;
  if (parsed.source === null) {
    try {
      report = await verifyArchive(bytes);
    } catch {
      io.err(`error: archive could not be read: ${parsed.archive}`);
      return EXIT_USAGE;
    }
  } else if (parsed.replay) {
    try {
      replayReport = await replayTrace(bytes, passphrase!);
      report = replayReport.verification;
    } catch {
      replayFailed = true;
      report = await unlockReport(bytes, passphrase!);
    }
  } else {
    report = await unlockReport(bytes, passphrase!);
  }

  const { lines, resultOk } = verifyLines(
    parsed.archive,
    manifest,
    report,
    parsed.replay,
    replayReport,
    replayFailed,
  );
  for (const line of lines) io.out(line);
  return resultOk ? EXIT_OK : EXIT_FAILED;
}
