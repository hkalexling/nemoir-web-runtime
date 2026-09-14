/**
 * Vendored copy of the meta repo's `docs/trace/schema/` tree.
 *
 * The frozen vectors are committed under `test-vectors/schema/` so this suite
 * runs in a standalone checkout (CI has no meta repo); the meta repo's
 * `docs/trace/validate_phase0.py` pins byte-identity. `test-vectors/` is not
 * in the npm `files` allowlist, so it never ships in the package.
 */

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** Root of this package (`src/__tests__` -> package dir). */
export const PACKAGE_ROOT = resolve(here, "..", "..");

/** Vendored `docs/trace/schema/` tree. */
export const SCHEMA_ROOT = resolve(PACKAGE_ROOT, "test-vectors", "schema");

/** The frozen payloads (`schema/test-vectors/`), e.g. `jcs/`, `vault/`. */
export const VECTORS_ROOT = resolve(SCHEMA_ROOT, "test-vectors");
