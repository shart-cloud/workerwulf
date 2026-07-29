import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { wcFetch, field, servedFromCache, driveFromRegion, distinctColos, firstFetch, wait, type RegionDrive, type RegionNamespace } from "./_wc.js";

// A single round of remote reads cannot tell "there is no shared upper tier" from
// "the upper tier has not filled yet". After this wait the probe re-reads from the
// same remote objects: if each one now returns the nonce IT created rather than the
// origin's, the entries are per-data-center and lag is excluded. Measured 2026-07-29
// — remote colos still held their own entries 45s after populate. Not a measurement:
// no verdict derives from the elapsed time itself.
const XPOP_PROPAGATION_MS = 15_000;

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
 * Arm 1 (single-PoP) re-reads the key from the invoking data center: the same
 * invocation_nonce proves the entry was served without re-executing the Worker.
 *
 * Arm 2 (cross-PoP) is the headline claim, and needs the key driven from data centers
 * that do not share a lower tier. `WC_REGION` Durable Objects pinned with
 * `locationHint` provide that (see wc-region-driver.ts): region 1 populates, regions 2
 * and 3 read. A repeated nonce in a CONFIRMED-DIFFERENT colo means the second region's
 * lower tier was filled from the shared upper tier rather than by running the Worker —
 * one response, global reach, and any poisoned entry (W-WC-03) inherits that reach.
 *
 * Measured 2026-07-29: the arm REFUTES the cross-PoP claim on this account — remote
 * colos re-executed the Worker and, on re-read, each served the entry it had created
 * itself. The amplification is therefore per-data-center, which bounds the blast
 * radius of W-WC-03 rather than extending it. That is a defensive result and the arm
 * is kept for regression: if Cloudflare's tiering behavior changes, this flips to
 * `confirmed` and the severity rises with it.
 *
 * The arm is only interpretable when the colo read-back confirms distinct data
 * centers; `locationHint` is a hint, and same-colo drives collapse arm 2 into arm 1.
 * Without the binding (pre-deploy) the probe still reports the single-PoP half as
 * `partial`, exactly as before.
 *
 * Deploy-only. Locally → blocked.
 */
export const wWc06: Probe = async ({ env, runId }) => {
  const victim = env.SVC_WC_VICTIM;
  const descr = "Workers Cache tiered-cache amplification — a populated entry is served without re-invoking the Worker (single-PoP re-read plus a region-pinned cross-PoP arm testing upper-tier reach)";
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

  // --- Arm 1: single-PoP, from the invoking data center. ---
  const key = `/wc/echo?probe=w-wc-06&run=${encodeURIComponent(runId)}`;
  const populate = await wcFetch(victim, key);
  const reread = await wcFetch(victim, key);
  const servedWithoutWorker = servedFromCache(populate, reread);

  // --- Arm 2: cross-PoP, via region-pinned Durable Objects. Sequential and on its
  // own key: region 1 must populate before regions 2/3 read, or a MISS in region 2
  // would only mean "arrived first", not "no upper tier". ---
  const ns = env.WC_REGION as RegionNamespace | undefined;
  const xKey = `/wc/echo?probe=w-wc-06x&run=${encodeURIComponent(runId)}`;
  let drives: RegionDrive[] = [];
  let crossPop: "confirmed" | "per-colo" | "unstable" | "same-colo" | "no-driver" | "error" = ns ? "error" : "no-driver";
  let recheckNonces: unknown[] = [];
  let crossPopNonce: unknown;
  let driveError: string | undefined;

  if (ns) {
    try {
      drives = [
        await driveFromRegion(ns, "wnam", runId, xKey),
        await driveFromRegion(ns, "weur", runId, xKey),
        await driveFromRegion(ns, "apac", runId, xKey),
      ];
      const [origin, ...readers] = drives;
      crossPopNonce = field(firstFetch(origin), "invocation_nonce");
      // Only readers that provably ran somewhere else can testify.
      const remote = readers.filter((r) => distinctColos(origin, r));
      const hitOrigin = (d: RegionDrive | undefined): boolean =>
        typeof crossPopNonce === "string" && field(firstFetch(d), "invocation_nonce") === crossPopNonce;

      if (remote.length === 0) {
        crossPop = "same-colo";
      } else if (remote.some(hitOrigin)) {
        crossPop = "confirmed";
      } else {
        // No remote hit on the first pass. Re-read the same objects (same names →
        // same data centers) after a wait, to separate "no shared tier" from "the
        // shared tier had not filled yet".
        await wait(XPOP_PROPAGATION_MS);
        const recheck = await Promise.all(
          remote.map((r) => driveFromRegion(ns, r.hint as "wnam" | "weur" | "apac", runId, xKey)),
        );
        recheckNonces = recheck.map((r) => field(firstFetch(r), "invocation_nonce"));
        crossPop = recheck.some(hitOrigin)
          ? "confirmed"
          : // Each remote returning the nonce IT created means that colo is serving
            // its own entry for this key — separate entries per data center.
            recheck.every((r, i) => {
              const own = field(firstFetch(remote[i]), "invocation_nonce");
              return typeof own === "string" && field(firstFetch(r), "invocation_nonce") === own;
            })
            ? "per-colo"
            : "unstable";
      }
    } catch (err) {
      crossPop = "error";
      drives = [];
      driveError = err instanceof Error ? err.message : String(err);
    }
  }

  const NOTES: Record<typeof crossPop, string> = {
    confirmed:
      "Cross-PoP amplification CONFIRMED: a data center that never ran the Worker served the identical invocation_nonce produced in another region — the entry reached it through the shared upper tier. One poisoned response (W-WC-03) therefore has global reach without the attacker touching every PoP.",
    "per-colo":
      "Cross-PoP amplification REFUTED (defensive, blast-radius bound): remote data centers never served the origin's nonce, and on re-read each returned the nonce IT had created — every colo holds its own entry for this key, so propagation lag is excluded as the explanation. A poisoned entry (W-WC-03) does NOT gain global reach for free; an attacker must land the poisoning in each data center whose traffic they want to affect. Scope: this account's cache configuration, workers.dev, this response shape.",
    unstable:
      "Cross-PoP arm INCONCLUSIVE: remote regions neither served the origin's nonce nor stably re-served their own, so neither amplification nor per-colo isolation is established. Most likely an entry was evicted mid-probe. Re-run.",
    "same-colo":
      "Cross-PoP arm INCONCLUSIVE: locationHint did not place the driver objects in different data centers (see region_colos), so the remote reads are indistinguishable from arm 1. Re-run; hints are best-effort.",
    "no-driver":
      "Cross-PoP arm not run: WC_REGION binding absent (expected pre-deploy). Single-PoP half only.",
    error:
      "Cross-PoP arm errored; see cross_pop_error. Single-PoP half stands on its own.",
  };

  return base({
    test_id: "W-WC-06",
    track: "worker",
    description: descr,
    // `accessible` requires the cross-PoP claim the probe is actually about;
    // single-PoP alone remains `partial`, as before.
    result: crossPop === "confirmed" ? "accessible" : servedWithoutWorker ? "partial" : "blocked",
    severity: crossPop === "confirmed" ? "high" : servedWithoutWorker ? "medium" : "informational",
    run_id: runId,
    tags: ["misconfig", "misconfig:cache"],
    details: {
      populate_nonce: field(populate, "invocation_nonce"),
      reread_nonce: field(reread, "invocation_nonce"),
      populate_cache_status: populate.cache_status,
      reread_cache_status: reread.cache_status,
      served_without_worker: servedWithoutWorker,
      tiered_crosspop: crossPop,
      cross_pop_origin_nonce: crossPopNonce,
      region_colos: drives.map((d) => ({ hint: d.hint, colo: d.colo, colo_error: d.colo_error })),
      region_nonces: drives.map((d) => field(firstFetch(d), "invocation_nonce")),
      region_cache_statuses: drives.map((d) => firstFetch(d).cache_status),
      remote_recheck_nonces: recheckNonces,
      cross_pop_error: driveError,
      note: NOTES[crossPop],
    },
    comparison: COMPARISON,
  });
};
