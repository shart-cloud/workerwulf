import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field, driveFromRegion, distinctColos, type RegionDrive, type RegionNamespace } from "./_wc.js";

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
 * timing-based, so the local-dev timer-clamping constraint does not corrupt it.
 *
 * A second arm bounds the SCOPE of the collapse: the same burst is fired from two
 * region-pinned `WC_REGION` Durable Objects at one fresh key. Collapsing is expected
 * to be per-data-center, so the bound is a defensive result — one execution per colo,
 * not one globally — which caps how many concurrent victims a single attacker-triggered
 * in-flight response can join. Confirming that bound matters as much as the attack: it
 * is the difference between a PoP-local and a global victim-joining primitive. Only
 * interpretable when the colo read-back confirms distinct data centers.
 *
 * Deploy-only. Locally → blocked.
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

  // --- Scope arm: the same burst, simultaneously from two regions, one fresh key.
  // Both regions must be in flight together or the second would simply hit the cache
  // the first left behind, which measures caching rather than collapsing.
  const ns = env.WC_REGION as RegionNamespace | undefined;
  const scopeKey = `/wc/echo?probe=w-wc-07x&run=${encodeURIComponent(runId)}`;
  let scope: "per-colo" | "global" | "same-colo" | "no-driver" | "error" = ns ? "error" : "no-driver";
  let drives: RegionDrive[] = [];
  let scopeError: string | undefined;

  if (ns) {
    try {
      drives = await Promise.all([
        driveFromRegion(ns, "wnam", runId, scopeKey, { count: CONCURRENCY, concurrent: true }),
        driveFromRegion(ns, "weur", runId, scopeKey, { count: CONCURRENCY, concurrent: true }),
      ]);
      const [a, b] = drives;
      const nonceSet = (d: RegionDrive | undefined): Set<string> =>
        new Set((d?.fetches ?? []).map((f) => field(f, "invocation_nonce")).filter((n): n is string => typeof n === "string"));
      const [na, nb] = [nonceSet(a), nonceSet(b)];
      const shared = [...na].some((n) => nb.has(n));
      scope = !distinctColos(a, b) ? "same-colo" : shared ? "global" : "per-colo";
    } catch (err) {
      scope = "error";
      drives = [];
      scopeError = err instanceof Error ? err.message : String(err);
    }
  }

  const SCOPE_NOTES: Record<typeof scope, string> = {
    "per-colo":
      "Scope BOUNDED (defensive): simultaneous bursts in two confirmed-different data centers produced disjoint nonce sets — each colo ran the Worker for itself. Collapsing joins concurrent victims within a data center, not globally, which caps the victim-joining blast radius to one PoP's concurrent traffic.",
    global:
      "ESCALATE: a nonce appeared in BOTH regions' bursts — a single execution served concurrent requests across data centers. Victim-joining is not PoP-local, so one attacker-triggered in-flight response can be joined by victims network-wide.",
    "same-colo":
      "Scope arm INCONCLUSIVE: locationHint did not place the driver objects in different data centers (see region_colos), so the two bursts cannot be attributed to different PoPs. Re-run; hints are best-effort.",
    "no-driver": "Scope arm not run: WC_REGION binding absent (expected pre-deploy).",
    error: "Scope arm errored; see scope_error. The single-PoP collapsing result stands on its own.",
  };

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
      collapse_scope: scope,
      region_colos: drives.map((d) => ({ hint: d.hint, colo: d.colo, colo_error: d.colo_error })),
      region_distinct_executions: drives.map(
        (d) => new Set(d.fetches.map((f) => field(f, "invocation_nonce")).filter((n) => typeof n === "string")).size,
      ),
      scope_error: scopeError,
      scope_note: SCOPE_NOTES[scope],
      note: workerRanOnce
        ? "All N concurrent requests were served by a single Worker execution — an attacker triggering the in-flight response joins every concurrent victim to it, and the collapse is itself an oracle for whether a key is being computed. See collapse_scope/scope_note for the measured cross-PoP bound."
        : `Observed ${distinct.size} execution(s) across ${responded} concurrent requests. Fewer executions than requests indicates partial collapsing; loopback concurrency may not fully reproduce edge collapsing — confirm from an external concurrent driver.`,
    },
    comparison: COMPARISON,
  });
};
