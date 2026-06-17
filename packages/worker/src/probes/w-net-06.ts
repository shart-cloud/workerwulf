import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

function measureGranularity(clock: () => number, samples: number): {
  unique_values: number;
  min_nonzero_delta: number;
  raw_first: number;
  raw_last: number;
} {
  const values: number[] = [];
  const seen = new Set<number>();
  for (let i = 0; i < samples; i++) {
    const v = clock();
    values.push(v);
    seen.add(v);
  }
  let minDelta = Infinity;
  for (let i = 1; i < values.length; i++) {
    const d = values[i]! - values[i - 1]!;
    if (d > 0 && d < minDelta) minDelta = d;
  }
  return {
    unique_values: seen.size,
    min_nonzero_delta: minDelta === Infinity ? 0 : minDelta,
    raw_first: values[0]!,
    raw_last: values[values.length - 1]!,
  };
}

export const wNet06: Probe = async ({ runId }) => {
  const N = 10000;
  const perfNow = measureGranularity(() => performance.now(), N);
  const dateNow = measureGranularity(() => Date.now(), N);

  return base({
    test_id: "W-NET-06",
    track: "worker",
    description: "Timing precision available to a Worker",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      samples: N,
      performance_now: perfNow,
      date_now: dateNow,
      time_origin: performance.timeOrigin ?? null,
    },
  });
};
