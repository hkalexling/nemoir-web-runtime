/**
 * NemoIR Web Runtime — public API surface.
 *
 * This package is the TypeScript port of `python/nemoir-runtime`. It owns
 * execution semantics: the state machine, policy enforcement, tool
 * dispatch, model integration, and event streaming — all framework-neutral
 * (no React required; the generated `main.tsx` is one consumer).
 *
 * See `docs/web-backend.md` for the full architecture.
 */

// Errors
export {
  NemoIRRuntimeError,
  ToolValidationError,
  MissingCapabilityError,
  ToolInvocationError,
  PolicyDeniedError,
  PolicyEvaluationError,
  StageOutputValidationError,
  DataUnavailableError,
  NoTransitionMatchedError,
  MaxStepsExceededError,
  WorkflowTimeoutError,
  WorkflowValidationError,
  ModelProviderError,
  ModelOutputValidationError,
} from "./errors.js";

// Capabilities
export {
  CAPABILITY_CATALOG,
  WEB_ALLOWED_CAPABILITIES,
  WEB_DETERMINISTIC_ONLY_CAPABILITIES,
  getCapability,
  isKnownCapability,
  isWebAllowedCapability,
  requiredParamNames,
  boundVarType,
  WRITE_TYPE_TO_JSON,
  type CapabilityParamType,
  type CapabilityParam,
  type CapabilitySpec,
} from "./capabilities.js";

// Events
export {
  WorkflowEventEmitter,
  type WorkflowEvent,
  type WorkflowEventKind,
  type WorkflowEventChannel,
  type WorkflowEventSink,
} from "./events.js";

// Canonical JSON (RFC 8785) + NemoTrace audit recorder
// (Phase 1: redacted single-file archives, no vault/replay yet).
export {
  canonicalStringify,
  toCanonicalBytes,
  parseJsonStrict,
} from "./canonical.js";
export {
  TraceRecorder,
  NoOpTraceRecorder,
  NO_OP,
  TraceError,
  TRACE_FORMAT,
  GRAPH_FORMAT,
  SUMMARY_FORMAT,
  CONTENT_IDENTITY_FORMAT,
  PROVENANCE_FORMAT,
  REDACTION_POLICY,
  SCANNER_RULESET,
  RUNTIME_NAME,
  RUNTIME_VERSION,
  MANIFEST_PATH,
  GRAPH_PATH,
  EVENTS_PATH,
  SUMMARY_PATH,
  INTEGRITY_PATH,
  VAULT_ENC_PATH,
  VAULT_META_PATH,
  VAULT_CODEC,
  VAULT_META_FORMAT,
  VAULT_AAD_FORMAT,
  VAULT_KDF_NAME,
  VAULT_KDF_ITERATIONS,
  VAULT_SALT_BYTES,
  VAULT_NONCE_BYTES,
  VAULT_DERIVED_KEY_BITS,
  VAULT_TAG_BITS,
  VAULT_PLAINTEXT_MEDIA_TYPE,
  VAULT_NULL_IR_SHA256,
  DEFAULT_MAX_VAULT_BYTES,
  AUDIT_ENTRY_PATHS,
  VAULT_ENTRY_PATHS,
  LIMIT_COMPRESSED_BYTES,
  LIMIT_UNCOMPRESSED_TOTAL_BYTES,
  LIMIT_UNCOMPRESSED_ENTRY_BYTES,
  LIMIT_EVENT_COUNT,
  generateTraceId,
  stableError,
  incompleteProvenance,
  safeModelDescriptor,
  verifyGeneratedProvenance,
  resolveRecorder,
  resolveTraceRecorder,
  writeArchive,
  readArchiveEntries,
  scanCleartextEntries,
  verifyArchive,
  unlockArchive,
  encryptVaultRecords,
  decryptVaultRecords,
  normalizePassphrase,
  checkVaultMeta,
  responseBytes,
  sha256Hex,
  type VaultCapture,
  type TraceConfig,
  type TraceStatus,
  type TraceValue,
  type HostProvenance,
  type ModelDescriptor,
  type VerificationReport,
} from "./trace.js";
export {
  TapedReplayError,
  TapedModelAdapter,
  TapedToolRegistry,
  replayTrace,
  manifestFromDict,
  type ReplayReport,
} from "./replay.js";
// Publication transform (Phase 5): audit -> attested, vault-free publication.
export {
  PUBLICATION_ATTESTATION_FORMAT,
  PUBLICATION_PROJECTION_FORMAT,
  PUBLICATION_REDACTION_POLICY,
  PUBLICATION_REPORT_FORMAT,
  PublicationError,
  attestationDocument,
  attestationFromDict,
  attestationFromReport,
  buildAttestation,
  preparePublication,
  publicationReport,
  publicationReportPath,
  scanPublication,
  serializeDocument,
  type PublicationAttestation,
  type PublicationOptions,
  type PublicationOptionsDict,
  type PublicationProjection,
  type PublicationResult,
  type PublicationSource,
  type PublicationStats,
} from "./publication.js";

// Runtime types
export {
  DEFAULT_RUN_OPTIONS,
  resolveRunOptions,
  DEFAULT_GENERATION_PARAMS,
  type RunOptions,
  type WorkflowState,
  type WorkflowResult,
  type AgentResult,
  type ModelGenerationParams,
  type ModelStageOutputValidationContext,
  type ModelStageOutputValidationResult,
  type ModelStageOutputValidator,
  type ModelStageOutputValidators,
} from "./runtime-types.js";

// UI Host
export { type WebUiHost } from "./ui-host.js";

// Tools
export {
  ToolRegistry,
  type Tool,
  type ToolContext,
  type ToolHandler,
  type ToolParamType,
} from "./tools.js";

// Model contract
export {
  supportsStreaming,
  resolveReasoningMode,
  modelForStage,
  type ModelAdapter,
  type ModelRequest,
  type ModelResponse,
  type ModelToolCall,
  type ModelStreamChunk,
  type ModelSpec,
  type ModelRouter,
} from "./model-contract.js";

// IR decoder
export {
  decodeWorkflowIr,
  validateForWeb,
  type WorkflowIrJson,
  type WebValidationIssue,
} from "./ir.js";

// Manifest
export {
  buildWorkflowManifest,
  type WorkflowManifest,
  type StageSpec,
  type ReadSpec,
  type WriteSpec,
  type TransitionSpec,
  type GuardSpec,
  type ExprSpec,
  type RefSpec,
  type PolicySpec,
  type TriggerSpec,
  type RequiredCapabilitySpec,
  type StageExecutionSpec,
} from "./manifest.js";

// Evaluator
export {
  evaluateGuard,
  evalExpr,
  resolveGuardRef,
  resolveReadRef,
  resolvePolicyRef,
  type GuardRefResolver,
  type PolicyRefContext,
} from "./evaluator.js";

// Runtime
export {
  WorkflowRuntime,
  readDisplayKey,
  type StageContext,
  type StageExecutor,
} from "./runtime.js";

// Model stage executor
export {
  ModelStageExecutor,
  outputSchemaForStage,
  normalizeStageOutput,
  toolResultToModelContent,
  toolJsonSchema,
  normalizeToolArgs,
  type ActionProtocol,
  type StageAction,
} from "./models.js";

// Agent factory
export {
  WorkflowAgent,
  type WorkflowAgentOptions,
} from "./agent.js";
export type { InputSpec } from "./manifest.js";

// WebLLM session + adapter (local in-browser inference)
export {
  createWebllmSession,
  createWebllmAdapter,
  WebLlmSessionImpl,
  isWebGPUAvailable,
  isCrossOriginIsolated,
  classifyLoadError,
  type WebLlmSession,
  type WebLlmSessionOptions,
  type WebLlmModelInfo,
  type WebLlmProgressReport,
  type StorageCapacityAssessment,
  type WebLlmLoadFailure,
  type WebLlmLoadPhase,
  type RetryLoadOptions,
  type DeleteAllModelArtifactsResult,
} from "./webllm.js";

// Deterministic stage executor
export {
  DeterministicStageExecutor,
  selectDeterministicTool,
} from "./deterministic.js";

// Browser-native tools
export {
  createBrowserTools,
  type BrowserToolsOptions,
  type HttpFetchResult,
  type JsRunOptions,
} from "./browser-tools.js";

// Dynamic-code sandbox
export {
  OpaqueOriginJsSandbox,
  createOpaqueOriginJsSandbox,
  DEFAULT_JS_SANDBOX_TIMEOUT_MS,
  DEFAULT_JS_SANDBOX_MAX_CODE_BYTES,
  DEFAULT_JS_SANDBOX_MAX_INPUT_BYTES,
  DEFAULT_JS_SANDBOX_MAX_OUTPUT_BYTES,
  OPAQUE_ORIGIN_SANDBOX_CSP,
  utf8ByteLength,
  type SandboxedJsRunner,
  type JsSandboxRequest,
  type OpaqueOriginJsSandboxOptions,
} from "./sandbox.js";

// WebGPU device-capability detection + model fit
export {
  SMALL_MODEL_VRAM_MB,
  probeDeviceCapabilities,
  assessModelFit,
  type WebGpuCapabilityReport,
  type DeviceStorageReport,
  type DeviceCapabilityReport,
  type ModelFitCategory,
  type ModelFitAssessment,
} from "./device-capabilities.js";

// Model-source / controlled-mirror profiles for WebLLM
export {
  mirrorModelId,
  toMirroredModelRecord,
  overlayModelRecords,
  type MirroredModelRecord,
  type ModelSourceProfile,
} from "./model-sources.js";
