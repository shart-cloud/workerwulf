import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wIso03: Probe = async ({ runId }) => {
  const out: Record<string, unknown> = {};

  out["SharedArrayBuffer_typeof"] = typeof (globalThis as unknown as {
    SharedArrayBuffer?: unknown;
  }).SharedArrayBuffer;

  try {
    const sab = new (globalThis as unknown as {
      SharedArrayBuffer: new (n: number) => ArrayBuffer;
    }).SharedArrayBuffer(8);
    out["SharedArrayBuffer_constructed"] = sab.byteLength === 8;
  } catch (err) {
    out["SharedArrayBuffer_constructed"] = false;
    out["SharedArrayBuffer_error"] =
      err instanceof Error ? err.message : String(err);
  }

  out["Atomics_typeof"] = typeof Atomics;
  out["Atomics_wait"] =
    typeof Atomics !== "undefined" && typeof Atomics.wait === "function";

  try {
    const mem = new WebAssembly.Memory({
      initial: 1,
      maximum: 1,
      shared: true,
    } as WebAssembly.MemoryDescriptor);
    out["WasmMemory_shared"] = mem.buffer.constructor.name;
  } catch (err) {
    out["WasmMemory_shared"] = false;
    out["WasmMemory_shared_error"] =
      err instanceof Error ? err.message : String(err);
  }

  const sabOK = out["SharedArrayBuffer_constructed"] === true;
  return base({
    test_id: "W-ISO-03",
    track: "worker",
    description: "SharedArrayBuffer / Atomics / shared Wasm memory availability",
    result: sabOK ? "accessible" : "blocked",
    severity: sabOK ? "medium" : "informational",
    run_id: runId,
    details: out,
  });
};
