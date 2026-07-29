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
 * These two mechanisms MUST be exercised on separate keys. The `Authorization`
 * auto-bypass is decided by the edge on the INBOUND request, before the Worker
 * runs, so sending that header suppresses caching outright and masks whether
 * heuristic freshness would have applied. Arm A therefore omits it (the heuristic
 * test); arm B sends it as the control that establishes the bypass still holds.
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

  // --- Arm A: heuristic freshness, NO Authorization (else the inbound auto-bypass
  // masks the result). Two different callers, one key.
  const key = `/wc/sensitive?probe=w-wc-05a&run=${encodeURIComponent(runId)}`;
  const first = await wcFetch(victim, key, { headers: { "x-wc-identity": "user-first" } });
  const firstSecret = field(first, "per_user_secret");
  const second = await wcFetch(victim, key, { headers: { "x-wc-identity": "user-second" } });
  const secondSecret = field(second, "per_user_secret");

  // --- Arm B: control. Same shape, but WITH Authorization on the request. If this
  // bypasses while arm A caches, the bypass is request-side and a Worker cannot
  // defeat it by stripping the header from the response.
  const ctrlKey = `/wc/sensitive?probe=w-wc-05b&run=${encodeURIComponent(runId)}`;
  const ctrl1 = await wcFetch(victim, ctrlKey, { headers: { "x-wc-identity": "user-first", authorization: "Bearer first-token" } });
  const ctrl2 = await wcFetch(victim, ctrlKey, { headers: { "x-wc-identity": "user-second", authorization: "Bearer second-token" } });
  const authBypassHeld = !servedFromCache(ctrl1, ctrl2);

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
      // Arm B control.
      auth_bypass_held: authBypassHeld,
      control_cache_status: ctrl2.cache_status,
      auth_bypass_note: authBypassHeld
        ? "Control: an Authorization request header still suppressed caching even though the Worker stripped it from the RESPONSE — the auto-bypass is decided inbound and is NOT defeatable by response-side normalization. This is a defensive result: forwarding Authorization is a safe-by-default path."
        : "Control: the Authorization auto-bypass did NOT hold — a response-side strip appears to defeat an inbound bypass. Escalate; this contradicts the documented behavior.",
      note: accidentallyCached
        ? "A per-user response with no Cache-Control was cached via heuristic freshness and replayed to a different caller. Set explicit Cache-Control: private/no-store on per-user responses."
        : "Not confirmed on this run — the edge may not apply heuristic freshness to this response shape, or the entry was not shared. Inspect second_user_secret vs first_user_secret and second_cache_status.",
    },
    comparison: COMPARISON,
  });
};
