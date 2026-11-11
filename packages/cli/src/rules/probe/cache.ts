import { registerProbe, type Finding } from "../../engine/rule.js";
import { httpEvidence, probeFinding, sameOriginUrl } from "./_utils.js";

/**
 * Every cache check runs on a URL carrying a fresh `wulfcb=<nonce>` query
 * parameter, so a poisoned entry lives only under a key no real user requests
 * — as long as the cache key includes the query string. A Worker that drops
 * the query from its cache key is itself a finding, but the probe then *could*
 * touch a real entry; the markers are inert `.invalid` hostnames for that
 * reason.
 */
function busted(url: string, nonce: string): string {
  const u = new URL(url);
  u.searchParams.set("wulfcb", nonce);
  return u.toString();
}

/** Headers commonly trusted for absolute-URL building but absent from cache keys. */
const UNKEYED_HEADERS = ["x-forwarded-host", "x-host", "x-forwarded-server", "x-original-host", "forwarded"];

registerProbe({
  id: "WF-DAST-CACHE-01",
  title: "Unkeyed request header poisons cached response",
  severity: "high",
  probe: "W-WC-*",
  family: "DAST",
  async check(ctx) {
    const findings: Finding[] = [];
    for (const path of ctx.paths) {
      for (const header of UNKEYED_HEADERS) {
        const token = `wulf-${ctx.nonce()}.invalid`;
        const url = busted(sameOriginUrl(ctx, path), ctx.nonce());
        const value = header === "forwarded" ? `host=${token}` : token;
        const poisoned = await ctx.http.request({ url, headers: { [header]: value } });
        if (!poisoned.body.includes(token) && !(poisoned.headers["location"] ?? "").includes(token)) continue;
        const clean = await ctx.http.request({ url });
        const persisted = clean.body.includes(token) || (clean.headers["location"] ?? "").includes(token);
        findings.push(
          probeFinding(
            this,
            url,
            persisted
              ? `${path}: the value of ${header} is reflected into the response AND served back to a later request that did not send it. The header is outside the cache key, so one request can rewrite this page (links, redirects, script URLs) for every visitor.`
              : `${path}: the value of ${header} is reflected into the response. It did not persist to a clean follow-up request, but any cache layer that keys on URL alone would make it stored poisoning.`,
            "Build absolute URLs from a configured canonical host, not request headers. If a header must influence the response, include it in the cache key (`new Request(keyUrl)` for ctx.cache / caches.default) or skip caching.",
            [
              httpEvidence(`with ${header}`, poisoned, { requestHeaders: { [header]: value } }),
              ...(persisted ? [httpEvidence("clean follow-up", clean)] : []),
            ],
            persisted ? "high" : "low",
          ),
        );
      }
    }
    return findings;
  },
});

registerProbe({
  id: "WF-DAST-CACHE-02",
  title: "Authenticated response served to anonymous caller from cache",
  severity: "critical",
  probe: "W-WC-04",
  family: "DAST",
  async check(ctx) {
    if (!ctx.auth) return []; // needs a credential to compare against
    const findings: Finding[] = [];
    const authHeaders = { [ctx.auth.name]: ctx.auth.value };
    for (const path of ctx.paths) {
      const base = sameOriginUrl(ctx, path);
      // 1. Is the route personalised at all? Compare authed vs anon on a cold key each.
      const authedCold = await ctx.http.request({ url: busted(base, ctx.nonce()), headers: authHeaders });
      const anonCold = await ctx.http.request({ url: busted(base, ctx.nonce()) });
      if (authedCold.status >= 400 || authedCold.body === anonCold.body) continue;
      // 2. Warm one key with the credential, then read it anonymously.
      const key = busted(base, ctx.nonce());
      const warm = await ctx.http.request({ url: key, headers: authHeaders });
      const leak = await ctx.http.request({ url: key });
      if (leak.body !== warm.body || leak.body === anonCold.body) continue;
      findings.push(
        probeFinding(
          this,
          key,
          `${path} is personalised (authenticated and anonymous bodies differ), but after one authenticated request the anonymous caller receives the authenticated body for the same URL. The cache key omits the caller's identity — the W-WC-04 cross-caller leak.`,
          "Never cache credentialed responses under a URL-only key. Add the principal (or a hash of it) to the cache key, mark per-user responses `Cache-Control: private, no-store`, or bypass ctx.cache / caches.default when Authorization or Cookie is present.",
          [
            httpEvidence("anonymous, cold key", anonCold),
            httpEvidence(`authenticated warm (${ctx.auth.name}: <redacted>)`, warm),
            httpEvidence("anonymous, same key", leak),
          ],
        ),
      );
    }
    return findings;
  },
});
