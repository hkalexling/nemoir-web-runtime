/**
 * NemoIR Web Runtime — error hierarchy.
 *
 * Mirrors `python/nemoir-runtime/src/nemoir_runtime/errors.py` exactly:
 * 14 subclasses rooted at `NemoIRRuntimeError`. All are empty-bodied
 * subclasses carrying a message string.
 */

export class NemoIRRuntimeError extends Error {}

export class ToolValidationError extends NemoIRRuntimeError {}

export class MissingCapabilityError extends NemoIRRuntimeError {}

export class ToolInvocationError extends NemoIRRuntimeError {}

export class PolicyDeniedError extends NemoIRRuntimeError {}

export class PolicyEvaluationError extends NemoIRRuntimeError {}

export class StageOutputValidationError extends NemoIRRuntimeError {}

export class DataUnavailableError extends NemoIRRuntimeError {}

export class NoTransitionMatchedError extends NemoIRRuntimeError {}

export class MaxStepsExceededError extends NemoIRRuntimeError {}

export class WorkflowTimeoutError extends NemoIRRuntimeError {}

export class WorkflowValidationError extends NemoIRRuntimeError {}

export class ModelProviderError extends NemoIRRuntimeError {}

export class ModelOutputValidationError extends NemoIRRuntimeError {}
