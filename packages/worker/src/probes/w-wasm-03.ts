import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wWasm03: Probe = async ({ runId }) => {
  const details: Record<string, unknown> = {};

  const memWasm = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x0f, 0x03,
    0x60, 0x01, 0x7f, 0x01, 0x7f,
    0x60, 0x02, 0x7f, 0x7f, 0x00,
    0x60, 0x01, 0x7f, 0x01, 0x7f,
    0x03, 0x04, 0x03, 0x00, 0x01, 0x02,
    0x05, 0x04, 0x01, 0x01, 0x01, 0x80, 0x02,
    0x07, 0x1d, 0x04,
    0x03, 0x6d, 0x65, 0x6d, 0x02, 0x00, 0x00,
    0x04, 0x72, 0x65, 0x61, 0x64, 0x00, 0x01,
    0x05, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x02,
    0x07, 0x67, 0x72, 0x6f, 0x77, 0x4d, 0x65, 0x6d, 0x00, 0x03,
    0x0a, 0x17, 0x03,
    0x07, 0x00, 0x20, 0x00, 0x28, 0x02, 0x00, 0x0b,
    0x08, 0x00, 0x20, 0x00, 0x20, 0x01, 0x36, 0x02, 0x00, 0x0b,
    0x06, 0x00, 0x20, 0x00, 0x40, 0x00, 0x0b,
  ]);

  try {
    const result = await WebAssembly.instantiate(memWasm) as unknown as {
      instance: {
        exports: {
          mem: WebAssembly.Memory;
          read: (o: number) => number;
          write: (o: number, v: number) => void;
          growMem: (p: number) => number;
        };
      };
    };
    const { mem, read, write, growMem } = result.instance.exports;

    const pageSize = mem.buffer.byteLength / 65536;
    details.initial_pages = pageSize;
    details.module_loaded = true;

    // In-bounds write/read
    write(0, 0xdeadbeef);
    const v = read(0);
    details.in_bounds_read = v === (0xdeadbeef | 0);

    // OOB read
    try {
      read(65536);
      details.out_of_bounds_read = "no trap";
    } catch (err) {
      details.out_of_bounds_read_result = "trap";
      details.out_of_bounds_read_error = err instanceof Error ? err.message : String(err);
    }

    // OOB write
    try {
      write(65536, 42);
      details.out_of_bounds_write = "no trap";
    } catch (err) {
      details.out_of_bounds_write_result = "trap";
      details.out_of_bounds_write_error = err instanceof Error ? err.message : String(err);
    }

    // Memory grow
    try {
      const oldPages = growMem(1);
      details.grow_1_page = true;
      details.pages_after_grow = mem.buffer.byteLength / 65536;
    } catch (err) {
      details.grow_1_page = false;
      details.grow_error = err instanceof Error ? err.message : String(err);
    }

    // Grow to maximum
    let maxPages = 1;
    try {
      while (true) {
        growMem(1);
        maxPages++;
      }
    } catch {
      details.max_pages_reached = maxPages;
      details.max_memory_mb = Math.round((maxPages * 65536 / (1024 * 1024)) * 100) / 100;
    }
  } catch (err) {
    details.module_loaded = false;
    details.error = err instanceof Error ? err.message : String(err);
  }

  return base({
    test_id: "W-WASM-03",
    track: "worker",
    description: "Test Wasm linear memory boundary integrity and growth limits",
    result: "blocked",
    severity: "informational",
    run_id: runId,
    details,
  });
};