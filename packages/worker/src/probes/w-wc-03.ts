import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field, servedFromCache } from "./_wc.js";

const COMPARISON = {
  aws_lambda: "partial analog — classic CDN cache poisoning via unkeyed headers exists at CloudFront, but is a distribution-config choice, not a per-function default",
  azure_functions: "N/A — no code-owned response cache",
  gcp_functions: "partial analog — Cloud CDN unkeyed-header poisoning, config-owned not function-owned",
} as const;

/**
 * W-WC-03 — Unkeyed-input cache poisoning (integrity).
 *
 * The documented Workers Cache footgun: request headers are NOT part of the cache
 * key. WcVictim reflects the `x-wc-reflect` request header into its cached response
 * body for a fixed (keyed) path. An attacker seeds the shared entry with a poison
 * value; a victim requesting the SAME path — with a different header, or none —
 * receives the ATTACKER's content from cache, with the Worker not re-invoked
 * (identical invocation_nonce). One poisoned entry is then served to every caller
 * of that path (and, via the tiered upper tier, network-wide — see W-WC-06).
 *
 * Deploy-only. Locally → blocked.
 */
export const wWc03: Probe = async ({ env, runId }) => {
  const victim = env.SVC_WC_VICTIM;
  const descr = "Workers Cache unkeyed-input poisoning — an attacker-controlled request header (not in the cache key) poisons the shared cached response served to other callers";
  if (!victim) {
    return base({
      test_id: "W-WC-03",
      track: "worker",
      description: descr,
      target: "WcVictim /wc/reflect",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:cache"],
      details: { error: "SVC_WC_VICTIM binding not present (expected locally / pre-deploy)" },
      comparison: COMPARISON,
    });
  }

  const poison = `flag{w-wc-03-poison-${runId}}`;
  const key = `/wc/reflect?probe=w-wc-03&run=${encodeURIComponent(runId)}`;

  // 1. Attacker seeds the shared entry via the unkeyed header.
  const attacker = await wcFetch(victim, key, { headers: { "x-wc-reflect": poison } });
  const attackerNonce = field(attacker, "invocation_nonce");
  const attackerReflected = field(attacker, "reflected");

  // 2. Victim requests the SAME keyed path with a DIFFERENT header value.
  const victimBenign = "benign-victim-value";
  const victimResp = await wcFetch(victim, key, { headers: { "x-wc-reflect": victimBenign } });
  const victimReflected = field(victimResp, "reflected");

  // Poisoned iff the victim got the attacker's value back, served from cache
  // (same nonce → Worker not re-run) rather than their own benign value.
  const servedCached = servedFromCache(attacker, victimResp);
  const poisoned = victimReflected === poison && victimReflected !== victimBenign && servedCached;

  return base({
    test_id: "W-WC-03",
    track: "worker",
    description: descr,
    target: "WcVictim /wc/reflect",
    result: poisoned ? "accessible" : servedCached || attackerReflected === poison ? "partial" : "blocked",
    severity: poisoned ? "high" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:cache"],
    details: {
      poison_value: poison,
      attacker_reflected: attackerReflected,
      attacker_nonce: attackerNonce,
      victim_sent_header: victimBenign,
      victim_reflected: victimReflected,
      victim_cache_status: victimResp.cache_status,
      served_from_cache: servedCached,
      poisoned_content_served: poisoned,
      worker_reexecuted: !servedCached,
      note: poisoned
        ? "Victim received attacker-controlled content from a shared cache entry despite sending a different (unkeyed) header — classic cache poisoning on the new Workers Cache. Move any request-derived state into ctx.props or the URL to key it."
        : "Poisoning not confirmed on this run — the header may have been keyed, the entry not shared, or propagation lagged. Inspect victim_reflected vs poison_value.",
    },
    comparison: COMPARISON,
  });
};
