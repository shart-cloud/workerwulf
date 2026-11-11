// Stands in for "oxc-parser" inside workerd (see wrangler.jsonc `alias`).
// Wrangler compiles the .wasm import to a WebAssembly.Module at build time, so
// instantiation is synchronous and there is no fetch at runtime.
import wasmModule from "@oxc-parser/wasm/web/oxc_parser_wasm_bg.wasm";
import { initSync, parseSync as wasmParseSync } from "@oxc-parser/wasm/web/oxc_parser_wasm.js";

import { adaptWasmParser } from "./oxc-api.js";

initSync({ module: wasmModule });

export const parseSync = adaptWasmParser(wasmParseSync);
