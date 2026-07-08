import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field, servedFromCache } from "./_wc.js";

const COMPARISON = {
  aws_lambda: "partial analog — CloudFront CreateInvalidation exists but is a control-plane IAM action, not callable by ordinary function code with no per-call authz",
  azure_functions: "N/A — no code-owned response cache to purge",
  gcp_functions: "partial analog — Cloud CDN invalidation is a control-plane operation, not in-function",
} as const;

/**
 * W-WC-02 — Purge-driven DoS / cache eviction (capability blast radius).
 *
 * `ctx.cache.purge()` carries no per-call authz and no allowlist: ANY code in the
 * isolate — including injected/generated Track-4 code — can evict the entrypoint's
 * entire cache via `purgeEverything`, forcing every subsequent request back to the
 * Worker/origin (load + CPU-billing amplification), and can exhaust the plan's
 * shared purge rate-limit so that legitimate purges fail (poisoned/stale content
 * can no longer be evicted). This is the Workers-Cache instance of the threat
 * model's unmitigated financial-DoS line (T11), adjacent to W-CAP-09.
 *
 * Safeguard: the purge is issued INSIDE the WcVictim entrypoint (the cache owner)
 * and is scoped to that entrypoint's own cache — it never touches production zone
 * cache and issues a single run-tagged call, no flood.
 *
 * Deploy-only. Locally → blocked.
 */
export const wWc02: Probe = async ({ env, runId }) => {
  const victim = env.SVC_WC_VICTIM;
  const descr = "Workers Cache purge blast radius — ctx.cache.purge({purgeEverything}) evicts the entrypoint cache from unprivileged isolate code (DoS / cache-integrity)";
  if (!victim) {
    return base({
      test_id: "W-WC-02",
      track: "worker",
      description: descr,
      target: "ctx.cache.purge",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:cache", "misconfig:binding"],
      details: { error: "SVC_WC_VICTIM binding not present (expected locally / pre-deploy)" },
      comparison: COMPARISON,
    });
  }

  // 1. Seed a cacheable entry and confirm it is cached (nonce identity).
  const key = `/wc/echo?probe=w-wc-02&run=${encodeURIComponent(runId)}&tag=wc-victim`;
  const seed1 = await wcFetch(victim, key);
  const seed2 = await wcFetch(victim, key);
  const seededHit = servedFromCache(seed1, seed2);
  const seedNonce = field(seed1, "invocation_nonce");

  // 2. Purge everything, executed inside the cache-owning entrypoint.
  const purge = await wcFetch(victim, `/wc/purge?mode=everything&run=${encodeURIComponent(runId)}`, { method: "POST" });
  const purgeAvailable = field(purge, "purge_available") === true;
  const purgeSucceeded = field(purge, "purge_succeeded") === true;

  // 3. Re-fetch the same key: a fresh nonce (MISS) proves eviction. A repeated
  // nonce is inconclusive — global purge propagation can lag the immediate re-read.
  const after = await wcFetch(victim, key);
  const afterNonce = field(after, "invocation_nonce");
  const evicted = typeof afterNonce === "string" && afterNonce !== seedNonce;

  const accessible = purgeAvailable && purgeSucceeded && evicted;

  return base({
    test_id: "W-WC-02",
    track: "worker",
    description: descr,
    target: "ctx.cache.purge",
    result: accessible ? "accessible" : purgeAvailable && purgeSucceeded ? "partial" : "blocked",
    severity: accessible ? "high" : purgeSucceeded ? "medium" : "informational",
    run_id: runId,
    tags: ["misconfig", "misconfig:cache", "misconfig:binding"],
    details: {
      seeded_cached: seededHit,
      seed_nonce: seedNonce,
      seed_cache_status: seed2.cache_status,
      purge_available: purgeAvailable,
      purge_succeeded: purgeSucceeded,
      purge_result: field(purge, "purge_result") ?? null,
      purge_error: field(purge, "purge_error") ?? null,
      evicted,
      after_purge_nonce: afterNonce,
      after_purge_cache_status: after.cache_status,
      note: evicted
        ? "Unprivileged isolate code evicted the entire entrypoint cache; every subsequent request now re-invokes the Worker/origin (load amplification). Repeatable to exhaust the plan's shared purge rate-limit, blocking legitimate eviction of poisoned content."
        : "Purge issued; immediate re-read did not show a MISS — likely global-purge propagation lag rather than a failed purge. Re-run W-WC-02 with --sequential/--interval to confirm eviction after propagation.",
    },
    comparison: COMPARISON,
  });
};
