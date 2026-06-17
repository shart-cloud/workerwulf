import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const BORN_MS = Date.now();
const ageSamples: number[] = [];

export const wRun02: Probe = async ({ req, runId }) => {
  const age = Date.now() - BORN_MS;
  ageSamples.push(age);

  const seqValue = new URL(req.url).searchParams.get("seq");
  const isFirst = !seqValue || seqValue === "0";

  const resets = countResets(ageSamples);

  return base({
    test_id: "W-RUN-02",
    track: "worker",
    description:
      "Measure V8 isolate lifetime — record age on each invocation, detect resets",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      born_epoch_ms: BORN_MS,
      current_age_ms: age,
      current_age_sec: (age / 1000).toFixed(1),
      samples_collected: ageSamples.length,
      age_samples_ms: ageSamples.slice(-50),
      reset_count: resets,
      isolate_recycled: resets > 0,
      born_timestamp: new Date(BORN_MS).toISOString(),
      min_age_ms: Math.min(...ageSamples),
      max_age_ms: Math.max(...ageSamples),
      note: `Born at ${new Date(BORN_MS).toISOString()}, current age ${(age / 1000).toFixed(0)}s, ${resets} resets detected`,
    },
  });
};

function countResets(samples: number[]): number {
  let resets = 0;
  for (let i = 1; i < samples.length; i++) {
    if (samples[i]! < samples[i - 1]!) resets++;
  }
  return resets;
}