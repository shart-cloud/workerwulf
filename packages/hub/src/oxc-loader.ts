/**
 * oxc-parser's official workerd build (`@oxc-parser/binding-wasm32-wasip1/workerd`),
 * wrapped with oxc-parser's own result wrapper so `parseSync` returns exactly what
 * the native Node binding returns: `{ program, module, comments, errors }`.
 *
 * Shared by the Worker shim and the Node equivalence tests, so both exercise the
 * same WASM build.
 */
import { createInstance } from "@oxc-parser/binding-wasm32-wasip1/workerd";
import { wrap } from "oxc-parser/src-js/wrap.js";

export interface ParseOptions {
  sourceType?: "script" | "module";
  lang?: "js" | "jsx" | "ts" | "tsx";
}

export type ParseSync = (filename: string, source: string, options?: ParseOptions) => {
  program: unknown;
  errors: Array<{ message: string }>;
};

/**
 * Linear memory to reserve up front, in 64 KiB pages. The loader's default is
 * 1024 pages (64 MiB) of a Worker's 128 MiB; memory still grows on demand.
 */
export const INITIAL_MEMORY_PAGES = 1024;

export async function loadParser(
  wasmModule: WebAssembly.Module,
  initialMemoryPages = INITIAL_MEMORY_PAGES,
): Promise<{ parseSync: ParseSync; memoryBytes: () => number }> {
  const instance = await createInstance(wasmModule, { initialMemoryPages });
  const binding = instance.exports;
  return {
    parseSync: (filename, source, options) => wrap(binding.parseSync(filename, source, options)),
    memoryBytes: () => instance.memoryBytes,
  };
}
