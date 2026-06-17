import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wWasm01: Probe = async ({ runId }) => {
  const details: Record<string, unknown> = {};

  const answer42 = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x0a, 0x01, 0x06, 0x61, 0x6e, 0x73, 0x77, 0x65, 0x72, 0x00, 0x00,
    0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
  ]);

  // Direct instantiate from bytes
  try {
    const result = await WebAssembly.instantiate(answer42) as unknown as {
      instance: { exports: { answer: () => number } };
    };
    const fn = result.instance.exports.answer;
    details.compile_from_bytes = true;
    details.instantiate_from_bytes = true;
    details.returned_value = fn();
    details.return_correct = details.returned_value === 42;
  } catch (err) {
    details.compile_from_bytes = false;
    details.compile_error = err instanceof Error ? err.message : String(err);
  }

  // Instantiate with imports object
  try {
    const result = await WebAssembly.instantiate(answer42, {}) as unknown as {
      instance: { exports: { answer: () => number } };
    };
    const fn = result.instance.exports.answer;
    details.instantiate_with_imports = true;
    details.imports_value = fn();
  } catch (err) {
    details.instantiate_with_imports = false;
    details.imports_error = err instanceof Error ? err.message : String(err);
  }

  // Test instantiate from ArrayBuffer (simulating fetch result)
  try {
    const buf = answer42.buffer.slice(0);
    const result = await WebAssembly.instantiate(buf) as unknown as {
      instance: { exports: { answer: () => number } };
    };
    details.instantiate_from_buffer = true;
    details.buffer_value = result.instance.exports.answer();
  } catch (err) {
    details.instantiate_from_buffer = false;
    details.buffer_error = err instanceof Error ? err.message : String(err);
  }

  const canCompile = details.compile_from_bytes === true;

  return base({
    test_id: "W-WASM-01",
    track: "worker",
    description: "Test runtime Wasm compilation from raw bytes",
    result: canCompile ? "accessible" : "blocked",
    severity: canCompile ? "medium" : "informational",
    run_id: runId,
    details: {
      ...details,
      note: canCompile
        ? "Arbitrary Wasm can be compiled at runtime — enables obfuscated payload execution"
        : "Wasm compilation from bytes is blocked in this runtime",
    },
  });
};