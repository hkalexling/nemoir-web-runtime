# @nemoir/web-runtime

TypeScript runtime core for NemoIR — execute compiled agent workflows in
the browser as structured state machines with tool orchestration, policy
enforcement, model-backed stage execution, and live event streaming.

## Compiler references

NemoIR is a research-pilot compiler stack. Canonical workflow language, IR semantics, and browser-target behavior live in the public compiler repo:

- [Compiler repo](https://github.com/hkalexling/nemoir)
- [DSL and IR spec](https://github.com/hkalexling/nemoir/blob/master/docs/dsl-and-ir.md)
- [Web target guide](https://github.com/hkalexling/nemoir/blob/master/docs/targets/web.md)

## Status

**Phase 3 (WebLLM adapter + generic UI) is implemented** with
grammar-constrained JSON decoding for tool-less stages,
structured load-failure diagnostics and recovery, deployer-controlled
model-source profiles, device-capability probing and model-fit
classification, and bounded-output/repetition guards. The runtime
provides the full execution stack (state machine, guard/expr evaluator,
policy engine, `ModelStageExecutor`, events, `WorkflowAgent` factory) plus
a framework-neutral WebLLM session/adapter. The generated runner UI
(`main.tsx`) is a React consumer of this package and `@nemoir/web-ui`; the
runtime itself does not require React.

## Design

- **Framework-neutral.** This package does not require React. The
  generated `main.tsx` is one consumer; a vanilla or framework-less host
  can consume `agent.stream()` directly. React is an optional peer dep.
- **Backend-neutral.** It is a TypeScript port of `python/nemoir-runtime`,
  reproducing the same state-machine loop, guard/expression evaluator,
  output validation, policy enforcement, and event streaming semantics.
  The compiler docs above remain canonical for DSL/IR and web-target semantics.
- **Browser-safe only.** Ships implementations for `user.elicit` and
  `user.confirm` via an injected `WebUiHost`. No `fs.*`, no `os.shell`.
  Workflows needing them are rejected at compile time by
  `nemoir-backend-web`'s `validate_for_web`.
- **Grammar-constrained decoding.** Tool-less model stages inject
  `response_format: { type: "json_object", schema }` so WebLLM's xgrammar
  backend guarantees a structurally valid object. Tool-enabled stages
  retain the tagged-envelope protocol (no static schema can express
  "tool_call OR final"). Per-stage opt-out:
  `options.constrainedDecoding = false`.
- **Tolerant JSON parsing.** Strict `JSON.parse` first; `jsonrepair`
  fallback handles the full class of small-model mistakes (missing commas,
  quotes, brackets, trailing commas, Python literals, code fences).
- **Model-generation parameters.** `ModelGenerationParams` (temperature,
  maxTokens, frequencyPenalty, presencePenalty) resolved via
  `RunOptions.generationParams` with sensible defaults (0.2 temp, 1024
  maxTokens, 0.5 penalties) and forwarded to the model adapter.
- **Semantic model-output validators.** `RunOptions.modelOutputValidators`
  keyed by model-stage ID run inside the retry path; a returned error is
  fed back to the model through the normal retry loop.
- **WebLLM load-failure diagnostics + recovery.** `classifyLoadError()`
  produces a structured `WebLlmLoadFailure` (phase, failed URL,
  corrupt-cache flag). `retryLoad()` optionally deletes cached artifacts
  (`cleanCache`) and/or recreates the WebLLM worker (`freshWorker`).
  `deleteModelArtifacts()` clears one model's cached artifacts;
  `deleteAllModelArtifacts()` sweeps every model in the app's catalog,
  unloading the current model and reporting per-model failures.
- **Device capabilities + model fit.** `probeDeviceCapabilities()` probes
  WebGPU (shader-f16 support, storage buffer limit). `assessModelFit()`
  classifies each model (recommended, likely_ok, needs_download,
  oversized_vram, missing_feature, buffer_limit, unknown) to guide
  selection. Conservative: never blocks a load.
- **Deployer-controlled model sources.** `ModelSourceProfile` and
  `MirroredModelRecord` let deployers host MLC artifacts on institutional
  CDNs or object storage. `overlayModelRecords()` merges mirror records
  with source-specific `model_id` suffixes to avoid cross-origin cache
  corruption. Public mirrors are intentionally not wired by default.
- **Action protocol.** Model stages use a `tagged-envelope` protocol by
  default on the web target (`{"kind":"final","output":{...}}` /
  `{"kind":"tool_call","tool":"...","args":{...}}`), which works with
  small WebLLM models that lack reliable function-calling. Native OpenAI
  tool-calling is available as an opt-in per-adapter override.
- **Cancellation.** `RunOptions.signal` (an `AbortSignal`) propagates to
  model adapters (WebLLM `engine.interruptGenerate()`) and UI-host tools,
  and `WorkflowRuntime.stream()` aborts its background run on early
  consumer break.
- **Degenerate-repetition guard.** Detects repeating token/phrase tails
  during streaming and interrupts via `engine.interruptGenerate()`.
- **Empty-content rejection.** An empty provider response fails the run
  immediately rather than retrying (avoids degenerate echo loops on small
  models).
- **Dynamic code is explicit and policy-gated.** `browser.js.sandbox` is for
  a user input or prior model-stage output that a later deterministic stage
  executes only after `before browser.js.sandbox(code) requires user.confirm`.
  It is never exposed as a model-callable tool.

## Dynamic JavaScript sandbox

Keep `browser.js.run` for compile-time literal, trusted workflow-author code.
For run-time user or LLM source, use `browser.js.sandbox` in a deterministic
stage and declare the approval policy:

```nemo
policy { before browser.js.sandbox(code) requires user.confirm }
```

Generated browser apps wire `createOpaqueOriginJsSandbox()` automatically. It
creates a fresh opaque-origin iframe (`sandbox="allow-scripts"` without
`allow-same-origin`) with a strict CSP and a nested Worker. Dynamic code gets
only JSON input, no direct DOM/host-origin-storage/NemoIR-tool capability, CSP-restricted network APIs, and
must return a plain JSON object. Defaults are a 5-second timeout, 64 KiB code,
and 256 KiB input/output. The confirmation UI displays the source first.

This is strong browser isolation and containment, not a guarantee against
browser-engine exploits or CPU/memory exhaustion. Never pass secrets or
credentials to dynamic code. Hosts that manually construct an `Agent` must
provide a `jsSandboxRunner`, normally:

```ts
import { createOpaqueOriginJsSandbox } from "@nemoir/web-runtime";

const agent = new Agent({
  uiHost,
  browserTools: { jsSandboxRunner: createOpaqueOriginJsSandbox() },
});
```

## WebLLM adapter

`@mlc-ai/web-llm` is a dependency but is **lazy-imported** via dynamic
`import("...")`, so it is code-split into a separate bundle chunk that
only loads when a local model is actually requested. Apps that never use
WebLLM do not pay the (~6 MB) chunk on first paint.

```ts
import { createWebllmSession, isWebGPUAvailable } from "@nemoir/web-runtime";

if (isWebGPUAvailable()) {
  const session = await createWebllmSession({
    workerFactory: () =>
      new Worker(new URL("./webllm.worker.ts", import.meta.url), { type: "module" }),
    onProgress: (r) => console.log(r.text, r.progress),
  });
  await session.ensureLoaded("Qwen2.5-0.5B-Instruct-q4f16_1-MLC");
  const adapter = session.adapter; // implements ModelAdapter
  // Pass `adapter` to WorkflowAgent (or the generated Agent) as modelAdapter.
}
```

## Usage (via generated app)

```ts
import { Agent, type AgentInput } from "./agent";

const agent = new Agent({ modelAdapter, uiHost });
for await (const event of agent.stream(inputs)) {
  console.log(event.kind, event);
}
```

The generated `agent.ts` imports from `@nemoir/web-runtime` and wires the
runtime against the compiled `workflow.json`.

## Development

```bash
npx tsc --noEmit   # typecheck
npx vitest run     # tests (no GPU required — WebLLM is mocked)
```

## Releasing

Maintainers should follow [RELEASING.md](RELEASING.md); npm publication is
performed only by the trusted GitHub Actions workflow.
