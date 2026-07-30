// Shared helpers for the Wave 5 Workers Cache probes (W-WC-*). Each attack drives
// the deliberately-vulnerable WcVictim entrypoint over the SVC_WC_VICTIM loopback
// service binding, which consults the callee's cache exactly like an eyeball
// request (see docs/wave5-workers-cache.md).

export interface WcFetch {
  ok: boolean;
  status: number;
  cache_status: string | null;
  body: Record<string, unknown> | string | null;
  error?: string;
}

const VICTIM_ORIGIN = "https://wc-victim";

export async function wcFetch(
  victim: Fetcher,
  path: string,
  init?: RequestInit,
): Promise<WcFetch> {
  try {
    const res = await victim.fetch(new Request(`${VICTIM_ORIGIN}${path}`, init));
    const text = await res.text();
    let body: Record<string, unknown> | string;
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      body = text;
    }
    return { ok: res.ok, status: res.status, cache_status: res.headers.get("cf-cache-status"), body };
  } catch (err) {
    return { ok: false, status: 0, cache_status: null, body: null, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Wall-clock delay used ONLY to let an edge-side control-plane change (a cache
 * purge) propagate before re-reading. This is deliberately not a measurement: no
 * verdict is derived from how long it took, so it does not reintroduce the
 * host-clock dependency the nonce oracle exists to avoid. Deploy-only paths.
 */
export function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Regions used by the cross-PoP driver (W-WC-06/07). Deliberately far apart so a
 * shared upper cache tier is the only plausible explanation for a repeated nonce,
 * and ordered so the first entry populates.
 */
export const WC_REGIONS = ["wnam", "weur", "apac"] as const;
export type WcRegion = (typeof WC_REGIONS)[number];

/**
 * Drive the victim from a DO pinned to `hint`. Each region gets its own object name
 * (per run) because `locationHint` is honored only when the object is first created —
 * reusing one name across regions would silently pin every drive to the first region.
 */
export async function driveFromRegion(
  ns: RegionNamespace,
  hint: WcRegion,
  runId: string,
  path: string,
  opts: { count?: number; concurrent?: boolean; headers?: Record<string, string> } = {},
): Promise<RegionDrive> {
  const stub = ns.get(ns.idFromName(`wc-region-${hint}-${runId}`), { locationHint: hint });
  return stub.drive(hint, path, opts);
}

/** Structural types for the driver namespace, kept local so probes need no DO imports. */
export interface RegionDrive {
  hint: string;
  colo: string | null;
  colo_error?: string;
  fetches: WcFetch[];
}
export interface RegionNamespace {
  idFromName(name: string): unknown;
  get(id: unknown, opts?: { locationHint?: string }): { drive(hint: string, path: string, opts?: { count?: number; concurrent?: boolean; headers?: Record<string, string> }): Promise<RegionDrive> };
}

const NO_FETCH: WcFetch = { ok: false, status: 0, cache_status: null, body: null, error: "no fetch recorded for this drive" };

/** The drive's first response, or a sentinel — an empty drive must not read as a hit. */
export function firstFetch(d: RegionDrive | undefined): WcFetch {
  return d?.fetches[0] ?? NO_FETCH;
}

/**
 * Two drives are cross-PoP evidence only if they really ran in different data
 * centers. `locationHint` is a hint; without confirmed-distinct colos a repeated
 * nonce proves nothing beyond the single-PoP result.
 */
export function distinctColos(a: RegionDrive | undefined, b: RegionDrive | undefined): boolean {
  return typeof a?.colo === "string" && typeof b?.colo === "string" && a.colo !== b.colo;
}

/** Pull a field from a WcFetch JSON body, or undefined if the body is not an object. */
export function field(r: WcFetch, name: string): unknown {
  return r.body && typeof r.body === "object" ? (r.body as Record<string, unknown>)[name] : undefined;
}

/**
 * Timer-free cache-hit oracle: two fetches of the same key that come back with the
 * SAME `invocation_nonce` mean the second was served from cache (the Worker was not
 * re-invoked). Different nonces mean a real re-execution (MISS).
 */
export function servedFromCache(a: WcFetch, b: WcFetch): boolean {
  const na = field(a, "invocation_nonce");
  const nb = field(b, "invocation_nonce");
  return typeof na === "string" && na === nb;
}
