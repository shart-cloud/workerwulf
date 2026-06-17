import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

let cpuCrashData: { iterationsRun: number; elapsedMs: number } | null = null;
let cpuModuleStateReset = false;

export const wErr04: Probe = async ({ req, runId }) => {
  const seqValue = new URL(req.url).searchParams.get("seq");
  const seq = seqValue ? parseInt(seqValue, 10) : 0;
  const details: Record<string, unknown> = { seq };

  if (seq === 0) {
    // Phase 0: run a CPU-intensive loop with checkpoints
    const started = Date.now();
    let iterations = 0;
    const checkpointInterval = 10000;
    let lastCheckpoint = 0;

    try {
      // Perform repeated hashing as the CPU workload
      let data = "wulf-cpu-test-seed";
      while (true) {
        // Simple hash function — each iteration does real work
        for (let i = 0; i < 100; i++) {
          let h = 0;
          for (let j = 0; j < data.length; j++) {
            h = ((h << 5) - h + data.charCodeAt(j)) | 0;
          }
          data = h.toString(36);
        }
        iterations += 100;

        // Checkpoint: update module-scope data periodically
        if (iterations - lastCheckpoint >= checkpointInterval) {
          lastCheckpoint = iterations;
          cpuCrashData = {
            iterationsRun: iterations,
            elapsedMs: Date.now() - started,
          };
        }

        // Safety: stop after 10 million iterations to prevent indefinite loop
        if (iterations >= 10_000_000) break;
      }
    } catch (err) {
      details.catch_error = err instanceof Error ? err.message : String(err);
    }

    const elapsed = Date.now() - started;
    details.iterations_run = iterations;
    details.elapsed_wall_ms = elapsed;
    details.cpu_limit_hit = iterations < 10_000_000;
    details.last_checkpoint = cpuCrashData;

    if (iterations < 10_000_000) {
      details.note = "CPU limit likely hit before reaching max iterations";
    }
  } else {
    // Phase 1: check if isolate was recycled
    details.phase = "post-cpu-check";
    details.previous_cpu_data_survived = cpuCrashData !== null;
    details.isolate_recycled = cpuCrashData === null && cpuModuleStateReset;

    if (cpuCrashData) {
      details.previous_iterations = cpuCrashData.iterationsRun;
      details.previous_elapsed_ms = cpuCrashData.elapsedMs;
      details.note = "Module-scope data survived — isolate NOT recycled after CPU limit";
    } else if (cpuModuleStateReset) {
      details.note = "Isolate was recycled after CPU limit";
    } else {
      details.note = "No previous CPU crash state detected (first run or isolated recycled)";
    }

    // Set this for future runs
    cpuModuleStateReset = cpuCrashData === null;
  }

  return base({
    test_id: "W-ERR-04",
    track: "worker",
    description:
      "Hit CPU time limit and document termination behavior",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details,
    comparison: {
      aws_lambda: "CPU proportional to memory, 100ms-900s timeout",
      azure_functions: "230s max, CPU proportional to plan",
      gcp_functions: "CPU proportional to memory, 540s max",
    },
  });
};