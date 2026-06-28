import type { WorkerLoader } from "./loader.js";

/**
 * Runtime egress allowlist (RESULTS.md §7, item 1).
 *
 * The Worker Loader's `globalOutbound` accepts a Fetcher that ALL of the loaded
 * child worker's outbound `fetch()` subrequests are routed through. We load a
 * tiny proxy worker whose only job is to inspect the destination host of each
 * subrequest and either forward it (allowlisted) or reject it with a 403
 * (everything else). This closes every callback-based exfiltration regardless
 * of how the URL was obfuscated (`evade-b64-url`, `evade-indirect`, …): the
 * platform routes the subrequest to the proxy before the bytes ever leave, so
 * no amount of string-mangling in the generated code can bypass it.
 *
 * The proxy worker itself is loaded with `globalOutbound` left undefined (open
 * egress) so that its own forwarding `fetch()` can actually reach the network.
 */

const EGRESS_COMPAT_DATE = "2026-05-01";

/**
 * Parse the comma-separated `WULF_EGRESS_ALLOWLIST` var into a normalized host
 * list. Empty / missing → `[]`, which means deny-all (clean 403s for every
 * outbound). The attacker callback host (`callback.wulf.shart.cloud`) is
 * deliberately NOT a default entry — that exclusion is the whole point.
 */
export function parseAllowlist(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Canonical host-match spec. A host is allowed if it equals an allowlist entry
 * exactly, or is a subdomain of one (`api.example.com` matches `example.com`).
 * The inline proxy module below mirrors this logic — keep them in sync.
 */
export function isHostAllowed(host: string, allowlist: string[]): boolean {
  const h = host.toLowerCase();
  return h !== "" && allowlist.some((p) => h === p || h.endsWith("." + p));
}

/**
 * Source of the egress-proxy worker. Mirrors {@link isHostAllowed}; the
 * allowlist is injected via the loaded worker's `env.ALLOWLIST` binding.
 */
const EGRESS_PROXY_MODULE = `export default {
  async fetch(request, env) {
    let host = "";
    try { host = new URL(request.url).hostname.toLowerCase(); } catch {}
    const allow = Array.isArray(env.ALLOWLIST) ? env.ALLOWLIST : [];
    const ok = host !== "" && allow.some((p) => host === p || host.endsWith("." + p));
    if (!ok) {
      return new Response(
        JSON.stringify({ error: "egress_blocked", host, allowlist: allow }),
        { status: 403, headers: { "content-type": "application/json" } },
      );
    }
    return fetch(request);
  },
};
`;

/**
 * Load the egress-proxy worker and return its entrypoint Fetcher, suitable for
 * passing as a child worker's `globalOutbound`.
 */
export function buildEgressFetcher(loader: WorkerLoader, allowlist: string[]): Fetcher {
  const stub = loader.load({
    compatibilityDate: EGRESS_COMPAT_DATE,
    mainModule: "egress.js",
    modules: { "egress.js": EGRESS_PROXY_MODULE },
    env: { ALLOWLIST: allowlist },
    // globalOutbound left undefined => proxy keeps open egress so it can
    // forward allowlisted subrequests to the real network.
  });
  return stub.getEntrypoint();
}
