# @nemoir/web-runtime

TypeScript runtime core for NemoIR — execute compiled agent workflows in
the browser as structured state machines with tool orchestration, policy
enforcement, model-backed stage execution, and live event streaming.

## Status

**Phase 3 (WebLLM adapter + generic UI) is implemented.** The runtime
provides the full execution stack (state machine, guard/expr evaluator,
policy engine, `ModelStageExecutor`, events, `WorkflowAgent` factory) plus
a framework-neutral WebLLM session/adapter. The generated runner UI
(`main.tsx`) is a React consumer of this package; the runtime itself does
not require React.

## Design

- **Framework-neutral.** This package does not require React. The
  generated `main.tsx` is one consumer; a vanilla or framework-less host
  can consume `agent.stream()` directly. React is an optional peer dep.
- **Backend-neutral.** It is a TypeScript port of `python/nemoir-runtime`,
  reproducing the same state-machine loop, guard/expression evaluator,
  output validation, policy enforcement, and event streaming semantics.
- **Browser-safe only.** Ships implementations for `user.elicit` and
  `user.confirm` via an injected `WebUiHost`. No `fs.*`, no `os.shell`.
  Workflows needing them are rejected at compile time by
  `nemoir-backend-web`'s `validate_for_web`.
- **Action protocol.** Model stages use a `tagged-envelope` protocol by
  default on the web target (`{"kind":"final","output":{...}}` /
  `{"kind":"tool_call","tool":"...","args":{...}}`), which works with
  small WebLLM models that lack reliable function-calling. Native OpenAI
  tool-calling is available as an opt-in per-adapter override.
- **Cancellation.** `RunOptions.signal` (an `AbortSignal`) propagates to
  model adapters (WebLLM `engine.interruptGenerate()`) and UI-host tools,
  and `WorkflowRuntime.stream()` aborts its background run on early
  consumer break.

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
