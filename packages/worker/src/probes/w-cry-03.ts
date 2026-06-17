import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wCry03: Probe = async ({ runId }) => {
  const details: Record<string, unknown> = {};
  const SAMPLE_SIZE = 1024 * 1024;

  try {
    const buf = new Uint8Array(SAMPLE_SIZE);
    for (let offset = 0; offset < buf.length; offset += 65536) {
      crypto.getRandomValues(buf.subarray(offset, Math.min(offset + 65536, buf.length)));
    }

    const bins = new Array(256).fill(0);
    for (let i = 0; i < buf.length; i++) {
      bins[buf[i]!]++;
    }

    const expected = SAMPLE_SIZE / 256;
    let chiSquare = 0;
    let maxDeviation = 0;
    for (let b = 0; b < 256; b++) {
      const diff = bins[b]! - expected;
      chiSquare += (diff * diff) / expected;
      const dev = Math.abs(diff) / expected;
      if (dev > maxDeviation) maxDeviation = dev;
    }

    // Runs test
    const median = 128;
    let runs = 1;
    for (let i = 1; i < buf.length; i++) {
      const prevAbove = buf[i - 1]! >= median;
      const currAbove = buf[i]! >= median;
      if (prevAbove !== currAbove) runs++;
    }
    const runsExpected = SAMPLE_SIZE / 2 + 1;
    const runsDeviation = Math.abs(runs - runsExpected) / Math.sqrt(4096);

    // Shannon entropy
    let entropySum = 0;
    for (let b = 0; b < 256; b++) {
      if (bins[b]! > 0) {
        const p = bins[b]! / SAMPLE_SIZE;
        entropySum -= p * Math.log2(p);
      }
    }

    const topBytes = bins
      .map((count, byte) => ({ byte, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const chiSquarePassed = chiSquare > 200 && chiSquare < 310;

    Object.assign(details, {
      sample_size_bytes: SAMPLE_SIZE,
      top_10_bytes: topBytes,
      entropy_per_byte: entropySum.toFixed(4),
      chi_square: chiSquare.toFixed(2),
      chi_square_expected_range: "200-310 (255 df, p=0.05)",
      chi_square_pass: chiSquarePassed,
      runs_count: runs,
      runs_expected: runsExpected,
      runs_deviation: runsDeviation.toFixed(2),
      max_frequency_deviation: (maxDeviation * 100).toFixed(2) + "%",
      assessment: chiSquarePassed ? "passes basic randomness tests" : "fails chi-square test",
    });
  } catch (err) {
    details.error = err instanceof Error ? err.message : String(err);
  }

  return base({
    test_id: "W-CRY-03",
    track: "worker",
    description: "Assess crypto.getRandomValues() output quality",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details,
  });
};
