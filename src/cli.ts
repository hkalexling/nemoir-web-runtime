/**
 * `nemotrace-js` verifier CLI: integrity, structural, semantic, and replay checks.
 *
 * Usage: `nemotrace-js verify <archive> [--unlock SRC | --replay SRC]` where
 * `SRC` is `env:VAR` | `file:PATH` | `prompt`. Prints the same stable
 * line-oriented report as the Python `nemotrace` CLI (see
 * `docs/trace/schema/test-vectors/cli/` for the shared golden outputs) and
 * returns `0` when the requested level passed, `1` when it failed, and `2`
 * for usage errors. Passphrase values, vault plaintext, and stack traces are
 * never printed.
 */

import { readFileSync, statSync } from "node:fs";
import { basename } from "node:path";

import { parseJsonStrict } from "./canonical.js";
import { replayTrace } from "./replay.js";
import type { ReplayReport } from "./replay.js";
import { readArchiveEntries, unlockArchive, verifyArchive } from "./trace.js";
import type { VerificationReport } from "./trace.js";

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_USAGE = 2;
const MAX_DIAGNOSTICS = 10;
const MISSING = "-";

const USAGE = "usage: nemotrace-js verify <archive> [--unlock SRC | --replay SRC]";

export interface CliIO {
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
  readonly env: Record<string, string | undefined>;
  readonly readTextFile: (path: string) => string;
  readonly promptPassphrase: () => Promise<string | null>;
}

interface ParsedVerify {
  readonly archive: string;
  readonly source: string | null;
  readonly replay: boolean;
}

function parseArgs(argv: readonly string[], io: CliIO): ParsedVerify | null {
  const [command, ...rest] = argv;
  if (command !== "verify") {
    io.err(USAGE);
    io.err("error: expected the 'verify' command");
    return null;
  }
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
    promptPassphrase: () => readHiddenPassphrase("vault passphrase: "),
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

export async function main(argv: readonly string[], ioOverride: Partial<CliIO> = {}): Promise<number> {
  const io: CliIO = { ...defaultIO(), ...ioOverride };
  const parsed = parseArgs(argv, io);
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
