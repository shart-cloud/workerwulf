import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

let previousCrashSizes: number[] = [];
let isolateSurvivedOom: boolean | null = null;

export const wErr03: Probe = async ({ req, runId }) => {
  const seqValue = new URL(req.url).searchParams.get("seq");
  const seq = seqValue ? parseInt(seqValue, 10) : 0;

  const details: Record<string, unknown> = { seq };

  if (seq === 0) {
    // Phase 0: allocate until OOM
    const allocations: number[] = [];
    const retained: Uint8Array[] = [];
    const MB = 1024 * 1024;
    let lastSuccessful = 0;

    // Try allocating 1MB, 2MB, 4MB, 8MB, ... up to 1024MB
    for (const mb of [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]) {
      try {
        const buf = new Uint8Array(mb * MB);
        // Write a pattern to ensure memory is actually committed
        for (let i = 0; i < buf.length; i += buf.length / 256) {
          buf[i] = i & 0xff;
        }
        retained.push(buf);
        allocations.push(mb);
        lastSuccessful = mb;

        // Store in module scope so seq=1 can check
        previousCrashSizes = [...allocations];
        isolateSurvivedOom = null;
      } catch (err) {
        details.oom_error_type = err instanceof Error ? err.name : typeof err;
        details.oom_error_message = err instanceof Error ? err.message : String(err);
        break;
      }
    }

    details.allocations_before_oom = allocations.length;
    details.last_successful_allocation_mb = lastSuccessful;
    details.total_allocated_mb = allocations.reduce((a, b) => a + b, 0);
    details.retained_allocations = retained.length;
    details.allocation_sizes_mb = allocations;
    details.oom_reached = lastSuccessful < 1024;

    // If we survived this far, we didn't actually hit OOM
    isolateSurvivedOom = details.oom_reached !== true;
  } else {
    // Phase 1: check if isolate was recycled
    details.phase = "post-crash-check";

    if (seq === 1) {
      // Check if module-scope state survived
      details.previous_allocation_sizes = [...previousCrashSizes];
      details.isolate_recycled = previousCrashSizes.length === 0;
      details.previous_data_survived = previousCrashSizes.length > 0;

      if (isolateSurvivedOom === true) {
        details.note = "Isolate survived OOM attempt — memory limit not hit or not fatal";
      } else if (isolateSurvivedOom === false) {
        details.note = "Isolate recycled after OOM — module-scope state was reset";
      } else if (previousCrashSizes.length > 0) {
        details.note = "Isolate recycled after OOM, but module-scope data survived";
      } else {
        details.note = "Isolate was recycled (fresh module scope)";
      }
    }
  }

  return base({
    test_id: "W-ERR-03",
    track: "worker",
    description:
      "Approach memory limit, document OOM behavior and isolate recycling",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details,
    comparison: {
      aws_lambda: "OOM kills container, 128MB-3008MB limits",
      azure_functions: "OOM kills process, consumption plan ~1.5GB",
      gcp_functions: "OOM kills instance, 128MB-32GB limits",
    },
  });
};
