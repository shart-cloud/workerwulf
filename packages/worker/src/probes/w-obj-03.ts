import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wObj03: Probe = async ({ runId }) => {
  const details: Record<string, unknown> = {};

  const BufferCtor = (globalThis as Record<string, unknown>).Buffer as
    | { alloc(size: number): Uint8Array; allocUnsafe(size: number): Uint8Array }
    | undefined;

  if (!BufferCtor) {
    return base({
      test_id: "W-OBJ-03",
      track: "worker",
      description:
        "Test whether Buffer.allocUnsafe() returns uninitialized memory",
      result: "informational",
      severity: "informational",
      run_id: runId,
      details: {
        buffer_available: false,
        note: "Buffer global not available",
      },
    });
  }

  details.buffer_available = true;
  const heapSize = 4096;

  // Phase 1: fill the heap with a known pattern
  const pattern = BufferCtor.alloc(heapSize);
  for (let i = 0; i < heapSize; i++) pattern[i] = (i & 0xff) ^ 0xaa;

  // Phase 2: allocate and inspect
  const iterations = 100;
  const results: Array<{
    nonzero: number;
    maxByte: number;
    minByte: number;
    firstNonzero: number | null;
    preview: string;
  }> = [];

  for (let iter = 0; iter < iterations; iter++) {
    const buf = BufferCtor.allocUnsafe(heapSize);
    let nonzero = 0;
    let maxByte = 0;
    let minByte = 255;
    let firstNonzero: number | null = null;

    for (let i = 0; i < heapSize; i++) {
      const b = buf[i]!;
      if (b !== 0) {
        nonzero++;
        if (b > maxByte) maxByte = b;
        if (b < minByte) minByte = b;
        if (firstNonzero === null) firstNonzero = i;
      }
    }

    const previewBytes: number[] = [];
    for (let i = 0; i < Math.min(nonzero, 32); i++) {
      if (buf[i]! !== 0) previewBytes.push(buf[i]!);
    }

    results.push({
      nonzero,
      maxByte: nonzero > 0 ? maxByte : 0,
      minByte: nonzero > 0 ? minByte : 255,
      firstNonzero,
      preview: nonzero > 0
        ? previewBytes.map((b) => b.toString(16).padStart(2, "0")).join(" ")
        : "(all zeros)",
    });
  }

  // Phase 3: look for recognizable string patterns
  let recognizablePatterns = 0;
  const patternExamples: string[] = [];

  // re-allocate a fresh block and scan for ASCII strings
  const scanBuf = BufferCtor.allocUnsafe(heapSize * 4);
  const text = new TextDecoder("ascii", { fatal: false, ignoreBOM: true }).decode(scanBuf);
  const matches = text.match(/[ -~]{8,}/g);
  if (matches) {
    recognizablePatterns = matches.length;
    patternExamples.push(...matches.slice(0, 5));
  }

  const allocationsWithData = results.filter((r) => r.nonzero > 0);
  const maxNonzero = results.reduce((m, r) => Math.max(m, r.nonzero), 0);
  const uninitializedDetected = allocationsWithData.length > 0;

  details.iterations = iterations;
  details.heap_size_bytes = heapSize;
  details.allocations_with_nonzero_bytes = allocationsWithData.length;
  details.max_nonzero_byte_count = maxNonzero;
  details.nonzero_details = results.filter((r) => r.nonzero > 0).slice(0, 10);
  details.recognizable_patterns_found = recognizablePatterns > 0;
  details.recognizable_pattern_examples = patternExamples.slice(0, 5);
  details.summary =
    uninitializedDetected
      ? `${allocationsWithData.length}/${iterations} allocUnsafe calls returned non-zero bytes (max ${maxNonzero} bytes). ${recognizablePatterns > 0 ? "Recognizable string patterns detected!" : "No recognizable patterns."}`
      : "All allocUnsafe calls returned zeroed memory — Workers runtime zeroes buffers (differs from Node.js)";

  return base({
    test_id: "W-OBJ-03",
    track: "worker",
    description:
      "Test whether Buffer.allocUnsafe() returns uninitialized memory",
    result: uninitializedDetected ? "accessible" : "blocked",
    severity: uninitializedDetected ? "medium" : "informational",
    run_id: runId,
    details,
    comparison: {
      aws_lambda: "Buffer not available (no Node.js compat layer)",
      azure_functions: "accessible (allocUnsafe returns heap contents)",
      gcp_functions: "accessible (allocUnsafe returns heap contents)",
    },
  });
};
