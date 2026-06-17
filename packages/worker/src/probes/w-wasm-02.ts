import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wWasm02: Probe = async ({ runId }) => {
  const details: Record<string, unknown> = {};

  // JS side: measure unique performance.now values in tight loop
  const jsCount = 10000;
  let lastJs = performance.now();
  let jsUnique = 0;
  for (let i = 0; i < jsCount; i++) {
    const now = performance.now();
    if (now !== lastJs) {
      jsUnique++;
      lastJs = now;
    }
  }
  details.js_samples = jsCount;
  details.js_unique_values = jsUnique;

  // Wasm side: import performance.now, call via wasm
  // Minimal wasm: imports env.now and exports getNow
  const timerWasm = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7c,
    0x02, 0x0d, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x03, 0x6e, 0x6f, 0x77, 0x00, 0x00,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x0a, 0x01, 0x06, 0x67, 0x65, 0x74, 0x4e, 0x6f, 0x77, 0x00, 0x01,
    0x0a, 0x06, 0x01, 0x04, 0x00, 0x10, 0x00, 0x0b,
  ]);

  try {
    let wasmUnique = 0;
    let lastWasmNow = performance.now();
    const wasmNowSamples: number[] = [];
    let callCount = 0;

    const importObj = {
      env: {
        now() {
          callCount++;
          const t = performance.now();
          if (t !== lastWasmNow) {
            wasmUnique++;
            lastWasmNow = t;
          }
          if (wasmNowSamples.length < 20) wasmNowSamples.push(t);
          return t;
        },
      },
    };

    const result = await WebAssembly.instantiate(timerWasm, importObj) as unknown as {
      instance: { exports: { getNow: () => number } };
    };
    const getNow = result.instance.exports.getNow;

    for (let i = 0; i < 10000; i++) {
      getNow();
    }

    details.wasm_compile_ok = true;
    details.wasm_calls = callCount;
    details.wasm_unique_values = wasmUnique;
    details.wasm_sample_vals = wasmNowSamples;
    details.clock_clamping_applies_to_wasm = wasmUnique <= 1;

    // JS Date.now comparison
    let dateUnique = 0;
    let lastDate = Date.now();
    const dateSamples: number[] = [];
    for (let i = 0; i < 1000; i++) {
      const d = Date.now();
      if (d !== lastDate) {
        dateUnique++;
        lastDate = d;
      }
      if (dateSamples.length < 5) dateSamples.push(d);
    }
    details.js_date_now_unique = dateUnique;
    details.js_date_now_samples = dateSamples;
  } catch (err) {
    details.wasm_compile_ok = false;
    details.wasm_error = err instanceof Error ? err.message : String(err);
  }

  return base({
    test_id: "W-WASM-02",
    track: "worker",
    description: "Test whether clock clamping applies inside Wasm execution",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details,
  });
};