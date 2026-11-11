// The same WASM build the Worker uses, loaded in Node for equivalence tests.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { loadParser } from "./oxc-loader.js";

const require = createRequire(import.meta.url);
const wasmPath = require.resolve("@oxc-parser/binding-wasm32-wasip1/wasm.wasm");

export const parser = await loadParser(new WebAssembly.Module(readFileSync(wasmPath)));
export const parseSync = parser.parseSync;
