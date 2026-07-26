/**
 * NemoIR Web Runtime — capability catalog.
 *
 * Mirrors `compiler/crates/nemoir-ir/src/capabilities.rs` and
 * `python/nemoir-runtime/src/nemoir_runtime/capabilities.py`.
 *
 * The catalog is a closed set of five capabilities. On the web target,
 * only `user.elicit` and `user.confirm` are allowed (enforced at compile
 * time by `validate_for_web` and defensively re-checked at decode time).
 */

export type CapabilityParamType = "string" | "path" | "bool" | "json";

export interface CapabilityParam {
  readonly name: string;
  readonly type: CapabilityParamType;
  /** Whether this parameter is required for deterministic exec stages (default true). */
  readonly required?: boolean;
}

export interface CapabilitySpec {
  readonly name: string;
  readonly requiredParams: readonly CapabilityParam[];

  hasRequiredParam(name: string): boolean;
}

function makeSpec(
  name: string,
  params: readonly CapabilityParam[],
): CapabilitySpec {
  return {
    name,
    requiredParams: params,
    hasRequiredParam(n: string): boolean {
      return params.some((p) => p.name === n && p.required !== false);
    },
  };
}

const FS_READ: CapabilitySpec = makeSpec("fs.read", [
  { name: "path", type: "path" },
]);

const FS_WRITE: CapabilitySpec = makeSpec("fs.write", [
  { name: "path", type: "path" },
  { name: "content", type: "string" },
]);

const OS_SHELL: CapabilitySpec = makeSpec("os.shell", [
  { name: "command", type: "string" },
]);

const USER_ELICIT: CapabilitySpec = makeSpec("user.elicit", [
  { name: "question", type: "string" },
]);

const USER_CONFIRM: CapabilitySpec = makeSpec("user.confirm", [
  { name: "message", type: "string" },
]);

// Browser-native capabilities (web target only)
const HTTP_FETCH: CapabilitySpec = makeSpec("http.fetch", [
  { name: "url", type: "string" },
  { name: "method", type: "string" },
  { name: "headers", type: "json", required: false },
  { name: "body", type: "json", required: false },
]);

const BROWSER_STORAGE_READ: CapabilitySpec = makeSpec("browser.storage.read", [
  { name: "key", type: "string" },
]);

const BROWSER_STORAGE_WRITE: CapabilitySpec = makeSpec("browser.storage.write", [
  { name: "key", type: "string" },
  { name: "value", type: "json" },
]);

const BROWSER_JS_RUN: CapabilitySpec = makeSpec("browser.js.run", [
  { name: "code", type: "string" },
  { name: "input", type: "json" },
]);

export const CAPABILITY_CATALOG: Readonly<Record<string, CapabilitySpec>> = {
  "fs.read": FS_READ,
  "fs.write": FS_WRITE,
  "os.shell": OS_SHELL,
  "user.elicit": USER_ELICIT,
  "user.confirm": USER_CONFIRM,
  "http.fetch": HTTP_FETCH,
  "browser.storage.read": BROWSER_STORAGE_READ,
  "browser.storage.write": BROWSER_STORAGE_WRITE,
  "browser.js.run": BROWSER_JS_RUN,
};

/** Capabilities allowed on the web target (including deterministic-only ones). */
export const WEB_ALLOWED_CAPABILITIES: readonly string[] = [
  "user.elicit",
  "user.confirm",
  "http.fetch",
  "browser.storage.read",
  "browser.storage.write",
  "browser.js.run",
];

/** Capabilities allowed ONLY for deterministic (`exec:`) stages on web. */
export const WEB_DETERMINISTIC_ONLY_CAPABILITIES: readonly string[] = [
  "browser.js.run",
];

export function getCapability(name: string): CapabilitySpec | undefined {
  return CAPABILITY_CATALOG[name];
}

export function isKnownCapability(name: string): boolean {
  return name in CAPABILITY_CATALOG;
}

export function isWebAllowedCapability(name: string): boolean {
  return WEB_ALLOWED_CAPABILITIES.includes(name);
}

export function requiredParamNames(name: string): ReadonlySet<string> {
  const spec = getCapability(name);
  if (!spec) return new Set();
  return new Set(
    spec.requiredParams
      .filter((p) => p.required !== false)
      .map((p) => p.name),
  );
}

/**
 * Return the type of a trigger-bound variable for a given capability.
 * Used by policy expression type-checking.
 */
export function boundVarType(
  capability: string,
  paramName: string,
): CapabilityParamType | undefined {
  const spec = getCapability(capability);
  if (!spec) return undefined;
  return spec.requiredParams.find((p) => p.name === paramName)?.type;
}

/** Map a NemoIR type string to a JSON Schema fragment for model output. */
export const WRITE_TYPE_TO_JSON: Readonly<Record<string, Record<string, unknown>>> = {
  string: { type: "string" },
  bool: { type: "boolean" },
  path: { type: "string" },
  number: { type: "number" },
  json: {},
  "string[]": { type: "array", items: { type: "string" } },
};
