/**
 * NemoIR Web Runtime — UI host interface.
 *
 * Injected by the generated app, consumed by the runtime.
 * Framework-neutral: the runtime calls elicit()/confirm() via Promise.
 *
 * The interface carries an optional AbortSignal so long-running prompts
 * can be cancelled with the run.
 */

export interface WebUiHost {
  elicit(question: string, options?: string[], signal?: AbortSignal): Promise<string>;
  confirm(message: string, signal?: AbortSignal): Promise<boolean>;
}
