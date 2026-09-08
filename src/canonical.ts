/**
 * NemoIR Web Runtime — RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * TypeScript side of the shared cross-language contract in
 * `docs/trace/schema/README.md` §3. Mirrors `canonical.rs` (Rust) and
 * `canonical.py` (Python); all three pass the vectors in
 * `docs/trace/schema/test-vectors/jcs/`.
 *
 * Notes:
 * - `JSON.stringify` already implements ECMAScript number serialization,
 *   so floats need no custom formatting (unlike the Python port).
 * - Default `Array.prototype.sort()` orders UTF-16 code units, which is
 *   exactly the RFC 8785 key order.
 * - Output is UTF-8 bytes with no trailing LF.
 */

export function assertUnicodeScalarString(value: string): void {
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError("JCS rejects lone high surrogates");
      }
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError("JCS rejects lone low surrogates");
    }
  }
}

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/** Canonicalize a JSON value to an RFC 8785 string (no trailing LF). */
export function canonicalStringify(value: unknown): string {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("JCS rejects non-finite numbers");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    assertUnicodeScalarString(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalStringify(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    // Default sort() orders UTF-16 code units — the RFC 8785 key order.
    const keys = Object.keys(record).sort();
    for (const key of keys) {
      assertUnicodeScalarString(key);
    }
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${canonicalStringify(record[key])}`)
      .join(",")}}`;
  }
  throw new TypeError(`unsupported JSON value: ${typeof value}`);
}

const textEncoder = new TextEncoder();

/** Canonicalize a JSON value to RFC 8785 UTF-8 bytes (no trailing LF). */
export function toCanonicalBytes(value: unknown): Uint8Array {
  return textEncoder.encode(canonicalStringify(value));
}

/** SHA-256 of bytes rendered as `sha256:<64 lowercase hex>`. */
export async function sha256Tag(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  const hex = [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

/** Parse JSON strictly, rejecting duplicate object keys. */
export function parseJsonStrict(text: string): unknown {
  // JSON.parse keeps the last duplicate; detect via a reviver-side scan is
  // complex, so re-scan objects with a source-level check is overkill here.
  // Instead, round-trip: stringify each parsed object with sorted keys and
  // compare key counts against a regex-free structural walk is fragile.
  //
  // Pragmatic approach: use a custom recursive descent for objects only to
  // detect duplicates, then delegate to JSON.parse for values.
  detectDuplicateKeys(text);
  return JSON.parse(text);
}

function detectDuplicateKeys(text: string): void {
  // Minimal scanner: tracks string literals and object depth outside strings.
  // Throws on a repeated key within one object level.
  const stack: { kind: "object" | "array"; keys: Set<string> }[] = [];
  let i = 0;
  let inString = false;
  let stringValue = "";
  let stringIsKey = false;

  while (i < text.length) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") {
        const esc = text[i + 1];
        if (esc === "u") {
          const hex = text.slice(i + 2, i + 6);
          stringValue += String.fromCharCode(parseInt(hex, 16));
          i += 6;
        } else {
          const map: Record<string, string> = {
            '"': '"',
            "\\": "\\",
            "/": "/",
            b: "\b",
            f: "\f",
            n: "\n",
            r: "\r",
            t: "\t",
          };
          stringValue += map[esc] ?? esc;
          i += 2;
        }
        continue;
      }
      if (ch === '"') {
        inString = false;
        if (stringIsKey && stack.length > 0) {
          const top = stack[stack.length - 1];
          if (top.kind === "object") {
            if (top.keys.has(stringValue)) {
              throw new SyntaxError(`duplicate JSON object key: ${stringValue}`);
            }
            top.keys.add(stringValue);
          }
        }
        stringIsKey = false;
        i += 1;
        continue;
      }
      stringValue += ch;
      i += 1;
      continue;
    }
    if (ch === '"') {
      // A string is a key iff it opens where an object key is expected:
      // right after '{' or ',' at object level, i.e. the previous
      // significant char is '{' or ',' and we are in an object.
      let j = i - 1;
      while (j >= 0 && /\s/.test(text[j])) j -= 1;
      const prev = j >= 0 ? text[j] : "";
      const top = stack[stack.length - 1];
      stringIsKey = top !== undefined && top.kind === "object" && (prev === "{" || prev === ",");
      stringValue = "";
      inString = true;
      i += 1;
      continue;
    }
    if (ch === "{") {
      stack.push({ kind: "object", keys: new Set() });
      i += 1;
      continue;
    }
    if (ch === "}") {
      stack.pop();
      i += 1;
      continue;
    }
    if (ch === "[") {
      stack.push({ kind: "array", keys: new Set() });
      i += 1;
      continue;
    }
    if (ch === "]") {
      stack.pop();
      i += 1;
      continue;
    }
    i += 1;
  }
}
