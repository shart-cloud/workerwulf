import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field } from "./_wc.js";

const COMPARISON = {
  aws_lambda: "N/A — no request-collapsing tier; concurrent identical requests each invoke the function",
  azure_functions: "N/A — no equivalent collapsing",
  gcp_functions: "N/A — no function-owned request collapsing",
} as const;

const CONCURRENCY = 8;

/**
 * W-WC-07 — Request-collapsing victim-joining / concurrency oracle (side channel).
 *
 * When many requests for the same key arrive simultaneously, Cloudflare runs the
 * Worker ONCE and joins every waiting request to that single in-flight response
 * stream. Two consequences: (a) an attacker who triggers the in-flight response has
 * every concurrent victim joined to attacker-influenced content, and (b) whether a
 * key is currently being computed is observable — a concurrency oracle over other
 * callers' activity.
 *
 * The probe fires N concurrent loopback requests at a fresh key and counts distinct
 * invocation_nonces: exactly one distinct nonce across N responses proves the Worker
 * executed once while all N received the body (collapsing). This is nonce-based, not
 * timing-based, so the local-dev timer-clamping constraint does not corrupt it; the
 * cross-PoP scope remains edge-only. Deploy-only. Locally → blocked.
 */
export const wWc07: Probe = async ({ env, runId }) => {
  const victim = env.SVC_WC_VICTIM;
  const descr = "Workers Cache request collapsing — N concurrent same-key requests are joined to one Worker execution (victim-joining + in-flight concurrency oracle)";
  if (!victim) {
    return base({
      test_id: "W-WC-07",
      track: "worker",
      description: descr,
      target: "WcVictim /wc/echo",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:cache"],
      details: { error: "SVC_WC_VICTIM binding not present (expected locally / pre-deploy)" },
      comparison: COMPARISON,
    });
  }

  // A fresh, never-cached key so the concurrent burst races on a cache MISS.
  const key = `/wc/echo?probe=w-wc-07&run=${encodeURIComponent(runId)}&n=${Date.now().toString(36)}`;
  const burst = await Promise.all(
    Array.from({ length: CONCURRENCY }, () => wcFetch(victim, key)),
  );

  const nonces = burst
    .map((r) => field(r, "invocation_nonce"))
    .filter((n): n is string => typeof n === "string");
  const distinct = new Set(nonces);
  const responded = nonces.length;
  const workerRanOnce = responded === CONCURRENCY && distinct.size === 1;

  return base({
    test_id: "W-WC-07",
    track: "worker",
    description: descr,
    target: "WcVictim /wc/echo",
    result: workerRanOnce ? "accessible" : distinct.size > 0 && distinct.size < responded ? "partial" : "blocked",
    severity: workerRanOnce ? "medium" : distinct.size < responded ? "low" : "informational",
    run_id: runId,
    tags: ["misconfig", "misconfig:cache"],
    details: {
      concurrency: CONCURRENCY,
      responded,
      distinct_executions: distinct.size,
      worker_ran_once: workerRanOnce,
      concurrent_joined: workerRanOnce ? CONCURRENCY : responded - distinct.size,
      inflight_oracle: distinct.size < responded,
      cache_statuses: burst.map((r) => r.cache_status),
      note: workerRanOnce
        ? "All N concurrent requests were served by a single Worker execution — an attacker triggering the in-flight response joins every concurrent victim to it, and the collapse is itself an oracle for whether a key is being computed. Cross-PoP scope is edge-only (collapsing is per data center)."
        : `Observed ${distinct.size} execution(s) across ${responded} concurrent requests. Fewer executions than requests indicates partial collapsing; loopback concurrency may not fully reproduce edge collapsing — confirm from an external concurrent driver.`,
    },
    comparison: COMPARISON,
  });
};
