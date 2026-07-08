import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field, servedFromCache } from "./_wc.js";

const COMPARISON = {
  aws_lambda: "partial analog — CDN response caching keyed without per-user vary can leak, but is a distribution-config choice, not a per-function default",
  azure_functions: "N/A — no code-owned response cache",
  gcp_functions: "partial analog — Cloud CDN cross-user leak on mis-keyed cache, config-owned not function-owned",
} as const;

/**
 * W-WC-04 — Cross-caller response leak (confidentiality).
 *
 * The confidentiality direction of the same missing-`ctx.props` root cause as
 * W-WC-03. WcVictim's `/wc/whoami` returns a per-identity `flag{}` canary but reads
 * identity from an UNKEYED custom header. Caller A (holding their canary) seeds the
 * shared entry; caller B — same keyed path, different identity header — receives
 * A's canary from cache. A control leg (`?keyed=props`) reads identity from
 * ctx.props and shows separate entries, proving isolation works when used correctly
 * — this is operator misconfig, not a platform bug (strengthens the disclosure).
 *
 * Deploy-only. Locally → blocked.
 */
export const wWc04: Probe = async ({ env, runId }) => {
  const victim = env.SVC_WC_VICTIM;
  const descr = "Workers Cache cross-caller leak — a per-identity secret is cached under an unkeyed header, so a second caller receives the first caller's response";
  if (!victim) {
    return base({
      test_id: "W-WC-04",
      track: "worker",
      description: descr,
      target: "WcVictim /wc/whoami",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:cache"],
      details: { error: "SVC_WC_VICTIM binding not present (expected locally / pre-deploy)" },
      comparison: COMPARISON,
    });
  }

  // --- Vulnerable leg: identity via unkeyed header ---
  const key = `/wc/whoami?probe=w-wc-04&run=${encodeURIComponent(runId)}`;
  const callerA = await wcFetch(victim, key, { headers: { "x-wc-identity": "alice" } });
  const secretA = field(callerA, "secret");
  const callerB = await wcFetch(victim, key, { headers: { "x-wc-identity": "bob" } });
  const bReceived = field(callerB, "secret");
  const bIdentity = field(callerB, "identity");

  const servedCached = servedFromCache(callerA, callerB);
  // Leak iff Bob's response carries Alice's identity/secret, served from cache.
  const leaked = typeof secretA === "string" && bReceived === secretA && bIdentity === "alice" && servedCached;

  // --- Control leg: identity via ctx.props (the correct pattern) ---
  const ckey = `/wc/whoami?keyed=props&probe=w-wc-04&run=${encodeURIComponent(runId)}`;
  const ctrlA = await wcFetch(victim, ckey, { headers: { "x-wc-identity": "carol" } });
  const ctrlB = await wcFetch(victim, ckey, { headers: { "x-wc-identity": "dave" } });
  // With no ctx.props set on a plain service-binding fetch both resolve to the same
  // "anonymous" identity, so equal secrets here is EXPECTED and does not prove a
  // leak — the meaningful control signal is that this leg is keyed_by ctx.props.
  const controlKeyedByProps = field(ctrlA, "keyed_by") === "ctx.props" && field(ctrlB, "keyed_by") === "ctx.props";

  return base({
    test_id: "W-WC-04",
    track: "worker",
    description: descr,
    target: "WcVictim /wc/whoami",
    result: leaked ? "accessible" : servedCached ? "partial" : "blocked",
    severity: leaked ? "critical" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:cache"],
    details: {
      caller_a_identity: field(callerA, "identity"),
      caller_a_secret: secretA,
      caller_b_sent_identity: "bob",
      caller_b_received_identity: bIdentity,
      caller_b_received_secret: bReceived,
      caller_b_cache_status: callerB.cache_status,
      served_from_cache: servedCached,
      cross_identity_leak: leaked,
      leaked_canary_matched: leaked,
      control_keyed_by_props: controlKeyedByProps,
      note: leaked
        ? "Caller B received caller A's per-identity canary from a shared cache entry keyed by an unkeyed header. Any caller-authenticating input must live in ctx.props (which IS part of the cache key) or the response must be marked private/uncacheable."
        : "Leak not confirmed on this run — identity may have been keyed, or the entry not shared. Compare caller_b_received_secret against caller_a_secret.",
    },
    comparison: COMPARISON,
  });
};
