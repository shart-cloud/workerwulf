import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field, servedFromCache } from "./_wc.js";

const COMPARISON = {
  aws_lambda: "N/A — no per-function edge response cache (CloudFront/Lambda@Edge is distribution-owned, configured out-of-band)",
  azure_functions: "N/A — no equivalent code-owned response cache",
  gcp_functions: "N/A — Cloud CDN is load-balancer-owned, not function-owned",
} as const;

/**
 * W-WC-01 — Workers Cache surface introspection.
 *
 * Baseline capability map for the new `ctx.cache` feature (distinct from the legacy
 * `caches.default` API covered by W-CACHE-*). Confirms (a) the purge API is present
 * inside the isolate and (b) the Worker's own responses are actually being cached,
 * proven by the timer-free nonce oracle: two loopback fetches of one cacheable key
 * that return the same invocation_nonce were served from cache without re-invoking
 * the Worker.
 *
 * Deploy-only: needs the edge cache layer + the WcVictim entrypoint wired. Locally
 * → blocked.
 */
export const wWc01: Probe = async ({ env, runId }) => {
  const victim = env.SVC_WC_VICTIM;
  const descr = "Workers Cache (ctx.cache) surface introspection — purge API presence + response-caching confirmation";
  if (!victim) {
    return base({
      test_id: "W-WC-01",
      track: "worker",
      description: descr,
      target: "ctx.cache / SVC_WC_VICTIM",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:cache"],
      details: { error: "SVC_WC_VICTIM binding not present (expected locally / pre-deploy)" },
      comparison: COMPARISON,
    });
  }

  const intro = await wcFetch(victim, "/wc/introspect");
  const cacheApiPresent = field(intro, "ctx_cache_present") === true;
  const hasPurge = field(intro, "ctx_cache_has_purge") === true;

  const key = `/wc/echo?probe=w-wc-01&run=${encodeURIComponent(runId)}`;
  const first = await wcFetch(victim, key);
  const second = await wcFetch(victim, key);
  const responseCached = servedFromCache(first, second);

  const accessible = cacheApiPresent && responseCached;

  return base({
    test_id: "W-WC-01",
    track: "worker",
    description: descr,
    target: "ctx.cache / SVC_WC_VICTIM",
    result: accessible ? "accessible" : cacheApiPresent || responseCached ? "partial" : "blocked",
    severity: "informational",
    run_id: runId,
    tags: ["misconfig", "misconfig:cache"],
    details: {
      cache_api_present: cacheApiPresent,
      purge_method_present: hasPurge,
      response_cached: responseCached,
      first_cache_status: first.cache_status,
      second_cache_status: second.cache_status,
      first_nonce: field(first, "invocation_nonce"),
      second_nonce: field(second, "invocation_nonce"),
      introspect_error: intro.error ?? null,
      note: "The cache belongs to the Worker/entrypoint (not a zone/domain). Presence of a code-driven purge API + automatic response caching is the surface the W-WC-02..07 blast-radius probes exploit.",
    },
    comparison: COMPARISON,
  });
};
