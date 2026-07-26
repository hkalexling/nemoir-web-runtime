/**
 * Release-gate test for `@nemoir/web-runtime`.
 *
 * Gated by `NEMOIR_RELEASE_VERIFY=1`: only runs when explicitly invoked.
 * Asserts that `npm pack`-ed tarball's built `dist` artifacts contain the
 * fixes claimed for the published version, so a stale build cannot ship
 * to the registry (the F1 reviewer finding).
 *
 * Run with: NEMOIR_RELEASE_VERIFY=1 npx vitest run src/__tests__/release-gate.test.ts
 */

import { describe, it, expect } from "vitest";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const enabled = process.env.NEMOIR_RELEASE_VERIFY === "1";

describe.skipIf(!enabled)("runtime release tarball gates", () => {
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoir-release-"));
  const fileRoot = path.resolve(__dirname, "../..");

  it("npm pack produces a tarball whose dist/runtime.js has no stale source-cap check", () => {
    const tarball = execSync("npm pack --pack-destination " + tmpdir, {
      cwd: fileRoot,
      encoding: "utf-8",
    }).trim();

    const tarPath = path.join(tmpdir, tarball);
    execSync(`tar xzf "${tarPath}"`, { cwd: tmpdir });

    const runtimeJs = fs.readFileSync(
      path.join(tmpdir, "package", "dist", "runtime.js"),
      "utf-8",
    );
    // The preflight now lives in browser-tools. Ensure the runtime does not
    // regress to the old sandboxApprovalMessage that reintroduces the DoS
    // path (the hard-coded DEFAULT_JS_SANDBOX_MAX_CODE_BYTES check).
    expect(runtimeJs).toContain("sandboxApprovalMessage");
    expect(runtimeJs).not.toContain("DEFAULT_JS_SANDBOX_MAX_CODE_BYTES");
  });

  it("dist/browser-tools.js carries the preflight hook", () => {
    const browserToolsJs = fs.readFileSync(
      path.join(tmpdir, "package", "dist", "browser-tools.js"),
      "utf-8",
    );
    expect(browserToolsJs).toContain("preflight");
    expect(browserToolsJs).toContain("utf8ByteLength");
  });

  it("dist/sandbox.js uses the async-function constructor", () => {
    const sandboxJs = fs.readFileSync(
      path.join(tmpdir, "package", "dist", "sandbox.js"),
      "utf-8",
    );
    expect(sandboxJs).toContain("async function");
    expect(sandboxJs).toContain("utf8ByteLength");
  });

  it("package.json version matches the checkout version", () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(tmpdir, "package", "package.json"), "utf-8"),
    );
    const rootPkg = JSON.parse(
      fs.readFileSync(path.join(fileRoot, "package.json"), "utf-8"),
    );
    expect(pkg.version).toBe(rootPkg.version);
  });
});
