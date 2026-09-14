/**
 * Tests for RFC 8785 canonicalization against shared NemoTrace vectors.
 *
 * Vectors live in the vendored `test-vectors/schema/test-vectors/jcs/` tree
 * (a byte-identical copy of the meta vectors; see `vectors.ts`).
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { VECTORS_ROOT } from "./vectors.js";

import {
  canonicalStringify,
  parseJsonStrict,
  sha256Tag,
  toCanonicalBytes,
} from "../canonical.js";

const JCS = join(VECTORS_ROOT, "jcs");
const IR = join(VECTORS_ROOT, "ir-fingerprint");

function float64FromHex(hex: string): number {
  const bytes = new ArrayBuffer(8);
  new DataView(bytes).setBigUint64(0, BigInt(`0x${hex}`), false);
  return new DataView(bytes).getFloat64(0, false);
}

describe("canonical", () => {
  it("matches the checked-in primitives vector", () => {
    const input = JSON.parse(readFileSync(join(JCS, "rfc8785-primitives.input.json"), "utf8"));
    const canonical = Buffer.from(toCanonicalBytes(input)).toString("utf8");
    expect(canonical).toBe(readFileSync(join(JCS, "rfc8785-primitives.canonical.json"), "utf8"));
  });

  it("matches the checked-in property-order vector", () => {
    const input = JSON.parse(
      readFileSync(join(JCS, "rfc8785-property-order.input.json"), "utf8"),
    );
    const canonical = Buffer.from(toCanonicalBytes(input)).toString("utf8");
    expect(canonical).toBe(
      readFileSync(join(JCS, "rfc8785-property-order.canonical.json"), "utf8"),
    );
  });

  it("matches all RFC 8785 number samples", () => {
    const samples = JSON.parse(
      readFileSync(join(JCS, "rfc8785-number-samples.json"), "utf8"),
    ) as { ieee754: string; json: string | null }[];
    for (const sample of samples) {
      const number = float64FromHex(sample.ieee754);
      if (sample.json === null) {
        expect(Number.isFinite(number)).toBe(false);
        expect(() => canonicalStringify(number)).toThrow(TypeError);
      } else {
        expect(JSON.stringify(number)).toBe(sample.json);
        expect(canonicalStringify(number)).toBe(sample.json);
      }
    }
  });

  it("rejects non-finite numbers and lone surrogates", () => {
    expect(() => canonicalStringify(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalStringify(Number.POSITIVE_INFINITY)).toThrow(TypeError);
    expect(() => canonicalStringify("\ud800")).toThrow(TypeError);
    expect(() => canonicalStringify("\udc00")).toThrow(TypeError);
  });

  it("rejects duplicate keys on strict parse", () => {
    expect(() => parseJsonStrict('{"a":1,"a":2}')).toThrow();
    expect(parseJsonStrict('{"a":1,"b":2}')).toEqual({ a: 1, b: 2 });
    expect(parseJsonStrict('["a","a"]')).toEqual(["a", "a"]);
  });

  it("matches the minimal-IR fingerprint vector", async () => {
    const input = JSON.parse(readFileSync(join(IR, "minimal-ir.input.json"), "utf8"));
    const canonical = Buffer.from(toCanonicalBytes(input)).toString("utf8");
    expect(canonical).toBe(readFileSync(join(IR, "minimal-ir.canonical.json"), "utf8"));
    const tag = await sha256Tag(toCanonicalBytes(input));
    expect(tag).toBe(readFileSync(join(IR, "minimal-ir.sha256"), "utf8").trim());
  });

  it("emits no trailing LF and sorts keys", () => {
    expect(canonicalStringify({ b: 1, a: [3, 2] })).toBe('{"a":[3,2],"b":1}');
  });
});
