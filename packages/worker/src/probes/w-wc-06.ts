import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field, servedFromCache } from "./_wc.js";

const COMPARISON = {
  aws_lambda: "N/A — CloudFront has regional edge caches but they are distribution-owned, not a per-function tier populated by the function's own responses",
  azure_functions: "N/A — no equivalent function-owned tiered cache",
  gcp_functions: "N/A — Cloud CDN tiering is load-balancer-owned, not function-owned",
} as const;

/**
 * W-WC-06 — Tiered-cache global amplification (blast-radius; edge-only half deferred).
 *
 * Workers Cache runs a lower tier (nearest data center) and a network-wide upper
 * tier that every lower tier consults on a miss. The first request for a key
 * anywhere populates the upper tier, so a single response is subsequently served
 * from cache across PoPs without re-invoking the Worker — amplifying any poisoned
 * entry (W-WC-03) to global reach.
 *
 * From one loopback invocation only the SINGLE-PoP half is observable: the entry is
 * served from cache without re-executing the Worker (timer-free nonce oracle). The
 * cross-PoP amplification requires driving the same key from >=2 Cloudflare regions
 * and is recorded as a documented, deferred edge-only caveat (mirrors the W-CAP-07
 * mTLS CF-egress deferral) — hence `partial`, not a failure.
 *
 * Deploy-only. Locally → blocked.
 */
export const wWc06: Probe = async ({ env, runId }) => {
  const victim = env.SVC_WC_VICTIM;
  const descr = "Workers Cache tiered-cache amplification — a populated entry is served without re-invoking the Worker (single-PoP proven; cross-PoP amplification deferred to a multi-region driver)";
  if (!victim) {
    return base({
      test_id: "W-WC-06",
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

  const key = `/wc/echo?probe=w-wc-06&run=${encodeURIComponent(runId)}`;
  const populate = await wcFetch(victim, key);
  const reread = await wcFetch(victim, key);
  const servedWithoutWorker = servedFromCache(populate, reread);

  return base({
    test_id: "W-WC-06",
    track: "worker",
    description: descr,
    target: "WcVictim /wc/echo",
    // Even when the single-PoP half is confirmed this stays `partial`: the headline
    // cross-PoP amplification claim is not demonstrated from one region.
    result: servedWithoutWorker ? "partial" : "blocked",
    severity: servedWithoutWorker ? "medium" : "informational",
    run_id: runId,
    tags: ["misconfig", "misconfig:cache"],
    details: {
      populate_nonce: field(populate, "invocation_nonce"),
      reread_nonce: field(reread, "invocation_nonce"),
      populate_cache_status: populate.cache_status,
      reread_cache_status: reread.cache_status,
      served_without_worker: servedWithoutWorker,
      tiered_crosspop: "deferred-edge-only",
      note: "Single-PoP: the entry was served from cache without re-invoking the Worker. Cross-PoP amplification (the upper-tier reach that makes a single poisoned entry global) requires a multi-region external driver — stand up curl from >=2 CF regions against the same key and confirm the second region hits without invoking the Worker. Tracked in docs/wave5-workers-cache.md Open items.",
    },
    comparison: COMPARISON,
  });
};
