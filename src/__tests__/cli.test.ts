/**
 * `nemotrace-js` CLI: golden outputs, exit codes, and passphrase sources.
 *
 * The golden stdout files under `docs/trace/schema/test-vectors/cli/` are
 * shared with the Python suite (`python/nemoir-runtime/tests/test_cli.py`)
 * and asserted by both, so the two CLIs provably agree byte-for-byte.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { main } from "../cli.js";
import type { CliIO } from "../cli.js";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..", "..", "..", "..");
const VECTORS = join(ROOT, "docs", "trace", "schema", "test-vectors");
const CLI_VECTORS = join(VECTORS, "cli");
const AUDIT_FIXTURE = join(VECTORS, "audit-valid.nemotrace");
const CVXPYGEN_FIXTURE = join(VECTORS, "cvxpygen-public.nemotrace");
const REPLAY_FIXTURE = join(CLI_VECTORS, "replay-e2e.nemotrace");
const VAULT_FIXTURE = join(CLI_VECTORS, "vault-fake-run.nemotrace");
const REPLAY_PASSPHRASE = "replay-e2e-passphrase";
const VAULT_PASSPHRASE = "phase4-vault-fake-passphrase-01";

interface RunResult {
  readonly code: number;
  readonly out: string;
  readonly err: string;
}

async function runCli(
  argv: readonly string[],
  env: Record<string, string | undefined> = {},
): Promise<RunResult> {
  const out: string[] = [];
  const err: string[] = [];
  const io: Partial<CliIO> = {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    env,
    readTextFile: (path) => readFileSync(path, "utf8"),
    promptPassphrase: async () => null,
  };
  const code = await main(argv, io);
  return { code, out: out.join("\n") + (out.length > 0 ? "\n" : ""), err: err.join("\n") };
}

function golden(name: string): string {
  return readFileSync(join(CLI_VECTORS, name), "utf8");
}

describe("nemotrace-js verify", () => {
  for (const [fixture, name] of [
    [AUDIT_FIXTURE, "expected-audit-valid.verify.txt"],
    [CVXPYGEN_FIXTURE, "expected-cvxpygen-public.verify.txt"],
    [VAULT_FIXTURE, "expected-vault-fake-run.verify.txt"],
  ] as const) {
    it(`verifies ${fixture.split("/").pop()} against the shared golden`, async () => {
      const result = await runCli(["verify", fixture]);
      expect(result.code).toBe(0);
      expect(result.out).toBe(golden(name));
    });
  }

  it("unlocks the replay fixture (env source) against the shared golden", async () => {
    const result = await runCli(["verify", REPLAY_FIXTURE, "--unlock", "env:NEMOTRACE_TEST_PW"], {
      NEMOTRACE_TEST_PW: REPLAY_PASSPHRASE,
    });
    expect(result.code).toBe(0);
    expect(result.out).toBe(golden("expected-replay-e2e.unlock.txt"));
  });

  it("unlocks the vault fixture against the shared golden", async () => {
    const result = await runCli(["verify", VAULT_FIXTURE, "--unlock", "env:NEMOTRACE_TEST_PW"], {
      NEMOTRACE_TEST_PW: VAULT_PASSPHRASE,
    });
    expect(result.code).toBe(0);
    expect(result.out).toBe(golden("expected-vault-fake-run.unlock.txt"));
  });

  it("taped-replays the replay fixture (file source) against the shared golden", async () => {
    const dir = mkdtempSync(join(tmpdir(), "nemotrace-cli-"));
    try {
      const secret = join(dir, "passphrase.txt");
      writeFileSync(secret, `${REPLAY_PASSPHRASE}\n`, "utf8");
      const result = await runCli(["verify", REPLAY_FIXTURE, "--replay", `file:${secret}`]);
      expect(result.code).toBe(0);
      expect(result.out).toBe(golden("expected-replay-e2e.replay.txt"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("wrong passphrase fails generically without echoing the value", async () => {
    const secret = "definitely-not-the-passphrase";
    const result = await runCli(["verify", REPLAY_FIXTURE, "--unlock", "env:NEMOTRACE_TEST_PW"], {
      NEMOTRACE_TEST_PW: secret,
    });
    expect(result.code).toBe(1);
    expect(result.out).toContain("error: vault unlock failed");
    expect(result.out).toContain("result: failed");
    expect(result.out).not.toContain(secret);
  });

  it("refuses taped replay on an audit archive", async () => {
    const result = await runCli(["verify", AUDIT_FIXTURE, "--replay", "env:NEMOTRACE_TEST_PW"], {
      NEMOTRACE_TEST_PW: REPLAY_PASSPHRASE,
    });
    expect(result.code).toBe(1);
    expect(result.out).toContain("replay: diverged");
    expect(result.out).toContain("divergence: archive has no replay vault");
    expect(result.out).toContain("replayability: playback-only");
    expect(result.out).toContain("result: failed");
  });

  it("missing archive is a usage error", async () => {
    const result = await runCli(["verify", join(tmpdir(), "missing.nemotrace")]);
    expect(result.code).toBe(2);
    expect(result.err).toContain("archive not found");
    expect(result.out).toBe("");
  });

  it("bad passphrase source is a usage error", async () => {
    const result = await runCli(["verify", AUDIT_FIXTURE, "--unlock", "bogus"]);
    expect(result.code).toBe(2);
    expect(result.err).toContain("expected env:VAR | file:PATH | prompt");
  });

  it("missing environment variable is a usage error", async () => {
    const result = await runCli(["verify", AUDIT_FIXTURE, "--unlock", "env:NEMOTRACE_MISSING_PW"], {});
    expect(result.code).toBe(2);
    expect(result.err).toContain("environment variable is missing or empty");
  });

  it("rejects mutually exclusive flags", async () => {
    const result = await runCli(["verify", AUDIT_FIXTURE, "--unlock", "prompt", "--replay", "prompt"]);
    expect(result.code).toBe(2);
    expect(result.err).toContain("mutually exclusive");
  });

  it("rejects unknown commands", async () => {
    const result = await runCli(["frobnicate"]);
    expect(result.code).toBe(2);
    expect(result.err).toContain("verify");
  });
});
