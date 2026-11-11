// The same WASM parser, loaded in Node, for equivalence tests against the native binding.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { initSync, parseSync as wasmParseSync } from "@oxc-parser/wasm/web/oxc_parser_wasm.js";

import { adaptWasmParser } from "./oxc-api.js";

const require = createRequire(import.meta.url);
initSync({ module: readFileSync(require.resolve("@oxc-parser/wasm/web/oxc_parser_wasm_bg.wasm")) });

export const parseSync = adaptWasmParser(wasmParseSync);
