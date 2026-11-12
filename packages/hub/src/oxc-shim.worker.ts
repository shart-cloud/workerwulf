// Stands in for "oxc-parser" inside workerd (see wrangler.jsonc `alias`).
// Wrangler compiles the .wasm import to a WebAssembly.Module at build time; the
// instance is created once per isolate, at module evaluation.
import wasmModule from "@oxc-parser/binding-wasm32-wasip1/wasm.wasm";

import { loadParser } from "./oxc-loader.js";

const parser = await loadParser(wasmModule);

export const parseSync = parser.parseSync;
export const wasmMemoryBytes = parser.memoryBytes;
