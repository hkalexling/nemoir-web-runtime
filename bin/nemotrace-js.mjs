#!/usr/bin/env node
/**
 * `nemotrace-js` binary: verify a NemoTrace archive.
 *
 * Thin wrapper over `../dist/cli.js`; see that module for the report and
 * exit-code contract, and `docs/trace/schema/test-vectors/cli/` for the
 * golden outputs shared with the Python `nemotrace` CLI.
 */
import { main } from "../dist/cli.js";

process.exitCode = await main(process.argv.slice(2));
