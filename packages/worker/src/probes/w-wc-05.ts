import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field, servedFromCache } from "./_wc.js";

const COMPARISON = {
  aws_lambda: "N/A — no automatic per-function response cache; heuristic freshness never applies to Lambda output",
  azure_functions: "N/A — no equivalent response cache",
  gcp_functions: "N/A — no function-owned response cache with RFC 9111 heuristic freshness",
} as const;

/**
 * W-WC-05 — Accidental caching of sensitive responses (operator misconfig).
 *
 * Two documented ways per-user content gets cached unintentionally:
 *   (1) Heuristic freshness — a response with NO explicit Cache-Control but a
 *       Last-Modified is cached via RFC 9111 heuristics.
 *   (2) Defeated auto-bypass — Set-Cookie on the response / Authorization on the
 *       request normally auto-bypass caching, but a Worker that strips or forwards
 *       those (a common gateway pattern) removes that protection.
 * WcVictim's `/wc/sensitive` returns a per-caller `flag{}` secret with no
 * Cache-Control + a stale Last-Modified and the bypass headers stripped. The probe
 * shows a second caller receiving the first caller's secret from cache.
 *
 * Deploy-only. Locally → blocked. May land `partial` if the edge declines to apply
 * heuristic freshness for this shape — recorded as a caveat, not a failure.
 */
export const wWc05: Probe = async ({ env, runId }) => {
  const victim = env.SVC_WC_VICTIM;
  const descr = "Workers Cache accidental caching — a per-user response with no Cache-Control (heuristic freshness) + defeated Set-Cookie/Authorization auto-bypass is cached and replayed to another caller";
  if (!victim) {
    return base({
      test_id: "W-WC-05",
      track: "worker",
      description: descr,
      target: "WcVictim /wc/sensitive",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:cache"],
      details: { error: "SVC_WC_VICTIM binding not present (expected locally / pre-deploy)" },
      comparison: COMPARISON,
    });
  }

  const key = `/wc/sensitive?probe=w-wc-05&run=${encodeURIComponent(runId)}`;
  const first = await wcFetch(victim, key, { headers: { "x-wc-identity": "user-first", authorization: "Bearer first-token" } });
  const firstSecret = field(first, "per_user_secret");
  const second = await wcFetch(victim, key, { headers: { "x-wc-identity": "user-second", authorization: "Bearer second-token" } });
  const secondSecret = field(second, "per_user_secret");

  const servedCached = servedFromCache(first, second);
  const cacheControlPresent = field(first, "cache_control_present") === true;
  // Accidental caching iff the second (different) user got the first user's secret
  // back from cache, and the response carried no explicit Cache-Control.
  const accidentallyCached =
    typeof firstSecret === "string" && secondSecret === firstSecret && servedCached && !cacheControlPresent;

  return base({
    test_id: "W-WC-05",
    track: "worker",
    description: descr,
    target: "WcVictim /wc/sensitive",
    result: accidentallyCached ? "accessible" : servedCached ? "partial" : "blocked",
    severity: accidentallyCached ? "high" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:cache"],
    details: {
      first_user_secret: firstSecret,
      second_user_secret: secondSecret,
      second_cache_status: second.cache_status,
      served_from_cache: servedCached,
      cache_control_present: cacheControlPresent,
      autobypass_headers_stripped: field(first, "autobypass_headers_stripped") === true,
      heuristic_cached: accidentallyCached,
      replayed_to_second_caller: accidentallyCached,
      note: accidentallyCached
        ? "A per-user response with no Cache-Control was cached via heuristic freshness and replayed to a different caller; the Set-Cookie/Authorization auto-bypass was defeated by the Worker normalizing those headers. Set explicit Cache-Control: private/no-store on per-user responses."
        : "Not confirmed on this run — the edge may not apply heuristic freshness to this response shape, or the entry was not shared. Inspect second_user_secret vs first_user_secret and second_cache_status.",
    },
    comparison: COMPARISON,
  });
};
