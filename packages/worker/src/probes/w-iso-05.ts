import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-ISO-05 — Timer resolution / clock precision.
 *
 * High-resolution, freely-advancing clocks are the precondition for timing
 * side-channels (Spectre-class cache-timing, cross-isolate observation). The
 * Cloudflare Workers runtime deliberately clamps timers — `Date.now()` does not
 * advance during purely synchronous computation, and `performance.now()` is
 * coarsened — to deny that primitive. This probe measures the observed
 * resolution and whether the clock advances without any intervening I/O.
 */
export const wIso05: Probe = async ({ runId }) => {
  const out: Record<string, unknown> = {};
  const SAMPLES = 200_000;

  // (1) Date.now() under pure compute — does it advance with no I/O?
  let acc = 0;
  let prev = Date.now();
  let distinct = 0;
  let minDelta = Infinity;
  let advanced = false;
  for (let i = 0; i < SAMPLES; i++) {
    acc += Math.sqrt(i + 1); // pure compute; keeps the loop from being elided
    const t = Date.now();
    if (t !== prev) {
      const d = t - prev;
      if (d > 0 && d < minDelta) minDelta = d;
      if (t > prev) advanced = true;
      prev = t;
      distinct++;
    }
  }
  out["dateNow_distinct_values"] = distinct;
  out["dateNow_min_nonzero_delta_ms"] = Number.isFinite(minDelta) ? minDelta : null;
  out["dateNow_advanced_during_pure_compute"] = advanced;
  out["_compute_sink"] = acc > 0;

  // (2) performance.now() resolution, if exposed at all.
  const perf = (globalThis as { performance?: { now?: () => number } }).performance;
  const perfAvailable = typeof perf?.now === "function";
  out["performance_now_available"] = perfAvailable;
  if (perfAvailable && perf?.now) {
    let acc2 = 0;
    let pPrev = perf.now();
    let pDistinct = 0;
    let pMin = Infinity;
    for (let i = 0; i < SAMPLES; i++) {
      acc2 += Math.sqrt(i + 1);
      const t = perf.now();
      if (t !== pPrev) {
        const d = t - pPrev;
        if (d > 0 && d < pMin) pMin = d;
        pPrev = t;
        pDistinct++;
      }
    }
    out["performance_now_distinct_values"] = pDistinct;
    out["performance_now_min_nonzero_delta_ms"] = Number.isFinite(pMin) ? pMin : null;
    out["_performance_sink"] = acc2 > 0;
  }

  // Three-state verdict, keyed off the same observation as the note:
  //   blocked     — clock frozen during sync compute (production-clamped)
  //   accessible  — sub-millisecond resolution (strong side-channel primitive)
  //   partial     — advances, but only at coarse (>=1ms) wall-clock resolution
  const subMs =
    advanced &&
    typeof out["dateNow_min_nonzero_delta_ms"] === "number" &&
    (out["dateNow_min_nonzero_delta_ms"] as number) < 1;
  const result = !advanced ? "blocked" : subMs ? "accessible" : "partial";
  const severity = result === "accessible" ? "medium" : result === "partial" ? "low" : "informational";

  out["note"] = !advanced
    ? "Clock did not advance during synchronous compute (timers clamped) — the Spectre-class timing primitive is denied at the source."
    : subMs
      ? "Clock advanced at sub-millisecond resolution during synchronous compute — a high-resolution timing side-channel primitive is present."
      : "Clock advanced only at coarse (>=1ms) resolution during synchronous compute — a usable but low-resolution timer.";
  out["caveat"] =
    "Local `wrangler dev` uses the host OS clock and does NOT reproduce production timer clamping; run against the deployed Worker for the real verdict.";

  return base({
    test_id: "W-ISO-05",
    track: "worker",
    description:
      "Timer resolution — does the isolate expose a high-resolution / freely-advancing clock usable for timing side-channels?",
    result,
    severity,
    run_id: runId,
    details: out,
    comparison: {
      aws_lambda:
        "accessible — full-resolution wall + monotonic clocks (timing side-channels feasible)",
      azure_functions: "accessible — full-resolution timers",
      gcp_functions: "accessible — full-resolution timers",
    },
  });
};
