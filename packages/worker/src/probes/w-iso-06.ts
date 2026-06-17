import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-ISO-06 — Counter-based clock amplification.
 *
 * Even when the real clock is clamped (see W-ISO-05), an attacker can try to
 * reconstruct a finer timer by counting busy-loop iterations between observable
 * clock ticks. That "amplified" timer is the precondition a timing side-channel
 * needs. This probe attempts the calibration: it spins a counter and checks
 * whether the real clock ever advances during a single synchronous turn. If it
 * never does within the spin budget, no in-turn timer can be calibrated and the
 * side-channel is denied at the source.
 */
export const wIso06: Probe = async ({ runId }) => {
  const MAX_SPIN = 5_000_000;

  const start = Date.now();
  let spins = 0;
  let moved = false;
  while (spins < MAX_SPIN) {
    spins++;
    if (Date.now() !== start) {
      moved = true;
      break;
    }
  }
  const elapsed = Date.now() - start;

  // If the clock advanced, report the amplification factor (spins per ms): how
  // many sub-tick events a counter-timer could in principle resolve.
  const amplification = moved && elapsed > 0 ? Math.round(spins / elapsed) : null;

  return base({
    test_id: "W-ISO-06",
    track: "worker",
    description:
      "Counter-based clock amplification — can a busy-loop timer be calibrated despite clamped clocks (timing side-channel precondition)?",
    result: moved ? "partial" : "blocked",
    severity: moved ? "medium" : "informational",
    run_id: runId,
    details: {
      spins,
      max_spin: MAX_SPIN,
      clock_moved_during_sync_compute: moved,
      elapsed_ms_after_loop: elapsed,
      counter_spins_per_observed_ms: amplification,
      note: moved
        ? "Real clock advanced during synchronous compute; a counter-based timer can be calibrated — a precondition for timing side-channels."
        : "Real clock did not advance across the spin budget within one synchronous turn — Cloudflare's timer model denies the calibration a timing side-channel needs.",
      caveat:
        "Local `wrangler dev` uses the host OS clock and does NOT reproduce production timer clamping; run against the deployed Worker for the real verdict.",
    },
    comparison: {
      aws_lambda: "n/a — native high-resolution timers make amplification unnecessary",
      azure_functions: "n/a — native high-resolution timers",
      gcp_functions: "n/a — native high-resolution timers",
    },
  });
};
