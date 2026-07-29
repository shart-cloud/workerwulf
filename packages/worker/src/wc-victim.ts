import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index.js";

/**
 * WcVictim — the deliberately-vulnerable *cached* entrypoint for the Wave 5
 * Workers Cache probes (W-WC-*). See docs/wave5-workers-cache.md.
 *
 * This is a named export so it can be (a) cached on its own via the Wrangler
 * per-entrypoint `exports` map — leaving the default `/probe/*` router UNcached so
 * the 60+ existing Track-1 probes keep their determinism (threat-model T4) — and
 * (b) driven by a probe over the `SVC_WC_VICTIM` loopback service binding, which
 * (per the docs) consults the callee entrypoint's cache exactly as an eyeball
 * request would.
 *
 * It intentionally implements the documented Workers Cache anti-patterns, keyed by
 * path so one entrypoint backs every attack probe. All secrets are benign,
 * run-tagged `flag{}` canaries — never real account data.
 */

// Module-global execution counter + the cache-hit oracle. Incremented on every
// REAL invocation. A cache HIT does not invoke the Worker, so a cached response
// carries the `invocation_nonce` captured when it was first written: identical
// nonces across two fetches of the same key prove the Worker was not re-executed.
// This is a timer-free oracle — it does not depend on the host clock, sidestepping
// the local-dev timer-clamping constraint.
let execCount = 0;

function identityCanary(identity: string): string {
  return `flag{w-wc-04-secret-for-${identity.replace(/[^a-z0-9-]/gi, "-").slice(0, 32)}}`;
}

// Distinct canary for /wc/sensitive so W-WC-05 results are not mislabelled with
// W-WC-04's flag tag (the two probes attack different mechanisms on this victim).
function sensitiveCanary(identity: string): string {
  return `flag{w-wc-05-secret-for-${identity.replace(/[^a-z0-9-]/gi, "-").slice(0, 32)}}`;
}

// `ctx.cache` / the `cloudflare:workers` cache export are newer than the pinned
// workers-types, so reach them through a narrow cast (same style the legacy cache
// probes use for `caches.default`).
type CachePurgeApi = {
  purge(opts: {
    tags?: string[];
    prefixes?: string[];
    purgeEverything?: boolean;
  }): Promise<unknown>;
};

export class WcVictim extends WorkerEntrypoint<Env> {
  override async fetch(req: Request): Promise<Response> {
    execCount += 1;
    const invocationNonce = crypto.randomUUID();
    const url = new URL(req.url);
    const path = url.pathname;

    const envelope = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
      entrypoint: "WcVictim",
      exec_count: execCount,
      invocation_nonce: invocationNonce,
      served_at: new Date().toISOString(),
      path,
      ...extra,
    });

    // A short cache window + a run-scoped Cache-Tag so the purge probe (W-WC-02)
    // has a tag to invalidate. NOTE: no Set-Cookie (would auto-bypass caching).
    const cacheTag = url.searchParams.get("tag") ?? "wc-victim";
    const cacheableHeaders: Record<string, string> = {
      "content-type": "application/json",
      "cache-control": "public, max-age=60",
      "cache-tag": cacheTag,
    };

    // --- W-WC-01: capability introspection (uncacheable control response) ---
    if (path === "/wc/introspect") {
      const ctxCache = (this.ctx as unknown as { cache?: CachePurgeApi }).cache;
      return this.uncacheable(
        envelope({
          ctx_cache_present: typeof ctxCache === "object" && ctxCache !== null,
          ctx_cache_has_purge:
            typeof (ctxCache as CachePurgeApi | undefined)?.purge === "function",
        }),
      );
    }

    // --- W-WC-02: purge, executed INSIDE the cache-owning entrypoint ---
    if (path === "/wc/purge") {
      const mode = url.searchParams.get("mode") ?? "everything";
      const ctxCache = (this.ctx as unknown as { cache?: CachePurgeApi }).cache;
      if (!ctxCache || typeof ctxCache.purge !== "function") {
        return this.uncacheable(
          envelope({ purge_available: false, note: "ctx.cache.purge unavailable (expected pre-deploy / no cache config)" }),
        );
      }
      const opts =
        mode === "tag"
          ? { tags: [url.searchParams.get("tag") ?? "wc-victim"] }
          : mode === "prefix"
            ? { prefixes: [url.searchParams.get("prefix") ?? "/wc/"] }
            : { purgeEverything: true };
      try {
        const purgeResult = await ctxCache.purge(opts);
        return this.uncacheable(
          envelope({ purge_available: true, purge_mode: mode, purge_opts: opts, purge_result: purgeResult ?? null, purge_succeeded: true }),
        );
      } catch (err) {
        return this.uncacheable(
          envelope({ purge_available: true, purge_mode: mode, purge_opts: opts, purge_succeeded: false, purge_error: err instanceof Error ? err.message : String(err) }),
        );
      }
    }

    // --- W-WC-03: unkeyed-input poisoning source. `x-wc-reflect` is a REQUEST
    // HEADER, which is NOT part of the cache key — so its value poisons the shared
    // entry for this (keyed) path. A query param would be keyed and would NOT
    // poison; the header is the whole point. ---
    if (path === "/wc/reflect") {
      return this.cacheable(
        envelope({ reflected: req.headers.get("x-wc-reflect") ?? null }),
        cacheableHeaders,
      );
    }

    // --- W-WC-04: cross-caller leak source. Identity comes from an UNKEYED custom
    // header instead of ctx.props, so caller B receives caller A's canary. The
    // `?keyed=props` control leg reads identity from ctx.props (the correct
    // pattern) to show isolation works when used properly. ---
    if (path === "/wc/whoami") {
      const useProps = url.searchParams.get("keyed") === "props";
      const propsIdentity = (this.ctx as unknown as { props?: { identity?: string } }).props?.identity;
      const identity = useProps
        ? propsIdentity ?? "anonymous"
        : req.headers.get("x-wc-identity") ?? "anonymous";
      return this.cacheable(
        envelope({ identity, secret: identityCanary(identity), keyed_by: useProps ? "ctx.props" : "unkeyed-header" }),
        cacheableHeaders,
      );
    }

    // --- W-WC-05: accidental caching. No explicit Cache-Control (RFC 9111
    // heuristic freshness via Last-Modified) and Set-Cookie/Authorization stripped
    // so the auto-bypass that would normally protect per-user content is defeated. ---
    if (path === "/wc/sensitive") {
      const caller = req.headers.get("x-wc-identity") ?? "anonymous";
      const headers: Record<string, string> = {
        "content-type": "application/json",
        // Deliberately NO cache-control → heuristic freshness.
        "last-modified": new Date(0).toUTCString(),
      };
      // A real gateway might attach Set-Cookie / forward Authorization here; the
      // victim "normalizes" them away, defeating the documented auto-bypass.
      return new Response(
        JSON.stringify(envelope({ per_user_secret: sensitiveCanary(caller), caller, cache_control_present: false, autobypass_headers_stripped: true }), null, 2),
        { headers },
      );
    }

    // --- Generic cacheable echo (W-WC-01/06/07 oracle) ---
    return this.cacheable(envelope(), cacheableHeaders);
  }

  private cacheable(body: Record<string, unknown>, headers: Record<string, string>): Response {
    return new Response(JSON.stringify(body, null, 2), { headers });
  }

  private uncacheable(body: Record<string, unknown>): Response {
    return new Response(JSON.stringify(body, null, 2), {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }
}
