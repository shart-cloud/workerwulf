import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index.js";
import { wcFetch, type WcFetch } from "./probes/_wc.js";

/**
 * WcRegionDriver — the multi-region driver for the Wave 5 cross-PoP open item
 * (W-WC-06 tiered amplification, W-WC-07 collapsing scope). See
 * docs/wave5-workers-cache.md.
 *
 * The cross-PoP half of those probes cannot be observed from a single loopback
 * invocation: everything runs in whichever data center served the eyeball request,
 * so the upper cache tier is never exercised. A Durable Object is the one primitive
 * in the account that lets Worker code choose *where* it runs — `locationHint` pins
 * a newly-created object to a region, and a service-binding fetch issued from inside
 * that object dispatches in the object's own data center. Driving `SVC_WC_VICTIM`
 * from objects pinned to different regions therefore runs WcVictim against different
 * lower tiers, with the shared upper tier in between — which is exactly the shape the
 * amplification claim is about.
 *
 * Two properties keep this honest:
 *   - `locationHint` is a HINT and is only applied at creation time. It is never
 *     assumed to have worked: every result carries the colo the object actually ran
 *     in, read back from `/cdn-cgi/trace`, and callers must confirm two results came
 *     from *different* colos before drawing a cross-PoP conclusion.
 *   - The verdict still rests on the `invocation_nonce` oracle, not on timing, so the
 *     local-dev timer-clamping constraint is not reintroduced.
 *
 * The object holds no storage. It exists only to be somewhere.
 */

export interface RegionDriveResult {
  /** The region hint requested at creation (not necessarily honored). */
  hint: string;
  /** The data center this object actually ran in, or null if the trace failed. */
  colo: string | null;
  /** Present only if the colo read-back failed; the drive itself may still be fine. */
  colo_error?: string;
  fetches: WcFetch[];
}

const TRACE_URL = "https://workers.cloudflare.com/cdn-cgi/trace";

export class WcRegionDriver extends DurableObject<Env> {
  /**
   * Fetch `path` from the cached victim entrypoint `count` times, from this object's
   * data center. `concurrent` fires them simultaneously (the W-WC-07 collapsing arm)
   * instead of sequentially.
   */
  async drive(
    hint: string,
    path: string,
    opts: { count?: number; concurrent?: boolean; headers?: Record<string, string> } = {},
  ): Promise<RegionDriveResult> {
    const { count = 1, concurrent = false, headers } = opts;
    const colo = await this.colo();
    const victim = this.env.SVC_WC_VICTIM;

    if (!victim) {
      return {
        ...colo,
        hint,
        fetches: [{ ok: false, status: 0, cache_status: null, body: null, error: "SVC_WC_VICTIM binding not present" }],
      };
    }

    const one = (): Promise<WcFetch> => wcFetch(victim, path, headers ? { headers } : undefined);
    const fetches = concurrent
      ? await Promise.all(Array.from({ length: count }, one))
      : await sequential(count, one);

    return { ...colo, hint, fetches };
  }

  /**
   * Read back the data center this object is running in. A subrequest to
   * `/cdn-cgi/trace` is answered by the nearest PoP, which for Worker-originated
   * traffic is the one executing the code. Failure is non-fatal — it costs the
   * cross-PoP *attribution*, not the nonce evidence — so it is reported, not thrown.
   */
  private async colo(): Promise<{ colo: string | null; colo_error?: string }> {
    try {
      const res = await fetch(TRACE_URL, { cf: { cacheTtl: 0 } } as RequestInit);
      const text = await res.text();
      const match = /^colo=(.+)$/m.exec(text);
      const colo = match?.[1]?.trim();
      return colo ? { colo } : { colo: null, colo_error: "no colo= line in trace" };
    } catch (err) {
      return { colo: null, colo_error: err instanceof Error ? err.message : String(err) };
    }
  }
}

async function sequential<T>(count: number, fn: () => Promise<T>): Promise<T[]> {
  const out: T[] = [];
  for (let i = 0; i < count; i += 1) out.push(await fn());
  return out;
}
