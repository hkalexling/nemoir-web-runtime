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

export type CapabilityParamType = "string" | "path" | "bool";

export interface CapabilityParam {
  readonly name: string;
  readonly type: CapabilityParamType;
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
      return params.some((p) => p.name === n);
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

export const CAPABILITY_CATALOG: Readonly<Record<string, CapabilitySpec>> = {
  "fs.read": FS_READ,
  "fs.write": FS_WRITE,
  "os.shell": OS_SHELL,
  "user.elicit": USER_ELICIT,
  "user.confirm": USER_CONFIRM,
};

/** Capabilities allowed on the web target. */
export const WEB_ALLOWED_CAPABILITIES: readonly string[] = [
  "user.elicit",
  "user.confirm",
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
  return new Set(spec.requiredParams.map((p) => p.name));
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
  "string[]": { type: "array", items: { type: "string" } },
};
