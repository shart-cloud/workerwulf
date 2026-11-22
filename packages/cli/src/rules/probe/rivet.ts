import { pathOf } from "../../dast/fingerprint.js";
import type { ProbeResponse } from "../../dast/http.js";
import { registerProbe, type Finding, type ProbeContext } from "../../engine/rule.js";
import { excerpt, httpEvidence, probeFinding, sameOriginUrl } from "./_utils.js";

/**
 * Rivet Engine / OpenOrange black-box DAST checks (source-verified against
 * rivet-dev/open-orange):
 *
 *  - Every OpenOrange Durable Object, facet, KV, D1, R2, Cache, Queue, Cron,
 *    and Workflow runs as a Rivet Actor in the project's namespace.
 *  - Unlike Cloudflare (where only the Worker can reach a DO), any caller with
 *    a Rivet Engine admin token or an `actor_gateway` grant can list actors via
 *    `GET /actors/names?namespace=default` / `GET /actors?namespace=default` and
 *    address them directly via `/gateway/<id>/request/__open-orange/durable-object/fetch`
 *    (bypassing the Worker and spoofing `request.cf`).
 *  - Local / misconfigured Rivet Engine uses the default admin token `Bearer default`.
 *  - Active OpenOrange migrations expose `POST /__migrate-d1/<binding>/<step>`
 *    (answering 401 `migrate_d1.unauthorized` when active).
 *  - RivetKit Prometheus metrics (`/metrics`) expose `rivet_rivetkit_actor_*`
 *    series naming active actor classes and traffic counts.
 */

function looksLikeActorNames(res: ProbeResponse): string[] | undefined {
  if (res.status !== 200) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(res.body);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const names = (parsed as { names?: unknown }).names;
  if (!names || typeof names !== "object" || Array.isArray(names)) return undefined;
  return Object.keys(names as Record<string, unknown>);
}

function isRivetAuthRejection(res: ProbeResponse): boolean {
  if (res.status !== 401 && res.status !== 403) return false;
  const header = res.headers["x-rivet-error"] ?? "";
  if (/^auth\./i.test(header)) return true;
  return /"group"\s*:\s*"auth"/.test(res.body);
}

function engineBases(ctx: ProbeContext): string[] {
  const bases: string[] = [];
  if (ctx.rivetEngine) bases.push(ctx.rivetEngine.origin);
  if (ctx.fingerprint.platform === "rivet" || ctx.fingerprint.platform === "openorange") {
    bases.push(ctx.target.origin);
  }
  return [...new Set(bases)];
}

registerProbe({
  id: "WF-DAST-RIVET-01",
  title: "Rivet Engine actor API exposed without authentication (or with default token)",
  severity: "critical",
  probe: "D-DO-*",
  family: "DAST",
  async check(ctx) {
    const findings: Finding[] = [];
    for (const base of engineBases(ctx)) {
      const url = `${base}/actors/names?namespace=default`;

      let res: ProbeResponse;
      try {
        res = await ctx.http.request({ url });
      } catch {
        continue;
      }

      let mode: "unauthenticated" | "default-token" | undefined;
      let names = looksLikeActorNames(res);
      if (names) {
        mode = "unauthenticated";
      } else if (isRivetAuthRejection(res)) {
        // Test whether the Engine was left with OpenOrange's documented local
        // dev admin token (`Authorization: Bearer default`). Read-only GET only.
        try {
          const defRes = await ctx.http.request({
            url,
            headers: { authorization: "Bearer default" },
          });
          names = looksLikeActorNames(defRes);
          if (names) {
            res = defRes;
            mode = "default-token";
          }
        } catch {
          // ignore network failure on follow-up
        }
      }

      if (!mode || !names) continue;
      const sample = names.slice(0, 8).join(", ");
      const accessDesc =
        mode === "unauthenticated"
          ? "answers `GET /actors/names?namespace=default` without any authentication"
          : 'accepts the default local dev admin token (`Authorization: Bearer default`) on `GET /actors/names?namespace=default`';
      findings.push(
        probeFinding(
          this,
          url,
          `Rivet Engine ${accessDesc} (${names.length} actor name(s) listed${sample ? `: ${sample}` : ""}). ` +
            "Because OpenOrange maps Durable Objects, KV, D1, Cache, and Queues to Rivet Actors, an attacker " +
            "with Engine access can enumerate actor IDs, mint `actor_gateway` tokens via `POST /auth/tokens`, " +
            "and invoke Durable Objects directly through `/gateway/<id>/request/__open-orange/durable-object/fetch` " +
            "(bypassing Worker auth and spoofing `request.cf`). Only the read-only listing endpoint was called.",
          "Require a strong, non-default Rivet Engine admin token, keep the Engine API on a private network " +
            "or behind strict ingress auth, and issue least-privilege client tokens without `actor_gateway` grants.",
          [
            httpEvidence(
              mode === "default-token" ? "GET /actors/names (Bearer default)" : "GET /actors/names",
              res,
              { body: excerpt(res.body, 500) },
            ),
          ],
        ),
      );
    }
    return findings;
  },
});

registerProbe({
  id: "WF-DAST-RIVET-02",
  title: "Rivet Engine / Gateway control plane reachable from scanner network",
  severity: "high",
  probe: "D-DO-*",
  family: "DAST",
  async check(ctx) {
    if (!ctx.rivetEngine) return [];
    const url = `${ctx.rivetEngine.origin}/actors/names?namespace=default`;
    let res: ProbeResponse;
    try {
      res = await ctx.http.request({ url });
    } catch {
      return [];
    }
    if (!isRivetAuthRejection(res)) return [];
    // Confirm default token didn't succeed (if it did, WF-DAST-RIVET-01 already reported Critical).
    try {
      const defRes = await ctx.http.request({ url, headers: { authorization: "Bearer default" } });
      if (looksLikeActorNames(defRes)) return [];
    } catch {
      // keep reporting reachability
    }
    return [
      probeFinding(
        this,
        url,
        `The Rivet Engine control-plane endpoint ${pathOf(url)} is reachable from this scanner and answered ` +
          `HTTP ${res.status} with Rivet auth rejection${res.headers["x-rivet-error"] ? ` (x-rivet-error: ${res.headers["x-rivet-error"]})` : ""}. ` +
          "Exposing the Engine API on an untrusted network turns any leaked `RIVET_ENDPOINT` or `actor_gateway` " +
          "token into direct Durable Object / Queue / D1 actor invocation.",
        "Keep self-hosted Rivet Engine listeners on a private network / overlay (WireGuard, Tailscale, VPC " +
          "internal load balancer) and restrict public ingress to the Worker front door.",
        [httpEvidence("GET /actors/names (unauthenticated)", res)],
      ),
    ];
  },
});

registerProbe({
  id: "WF-DAST-RIVET-03",
  title: "OpenOrange D1/DO live-migration route active on target",
  severity: "high",
  probe: "D-DO-*",
  family: "DAST",
  async check(ctx) {
    if (!ctx.allowPost) return [];
    // Only send the migration-route probe when the target looks like OpenOrange/Rivet
    // or is not a plain Cloudflare Workers edge host, to stay conservative.
    const url = sameOriginUrl(ctx, `/__migrate-d1/wulf-${ctx.nonce()}/status`);
    let res: ProbeResponse;
    try {
      res = await ctx.http.request({
        method: "POST",
        url,
        headers: { "content-type": "application/json" },
        body: "{}",
      });
    } catch {
      return [];
    }
    if (res.status !== 401 || !/"code"\s*:\s*"migrate_d1\.unauthorized"/.test(res.body)) {
      return [];
    }
    return [
      probeFinding(
        this,
        url,
        `POST ${pathOf(url)} returned HTTP 401 with OpenOrange's \`migrate_d1.unauthorized\` error, confirming ` +
          "`ORANGE_MIGRATE_WORKER_URL` and `WORKER_MIGRATOR_TOKEN` are actively mounted on this deployment. " +
          "While active, `/__migrate/*` and `/__migrate-d1/*` intercept traffic ahead of the Worker and expose " +
          "raw D1 query/import/discard and DO wake primitives to anyone holding `WORKER_MIGRATOR_TOKEN`.",
        "Unset `ORANGE_MIGRATE_WORKER_URL` and `WORKER_MIGRATOR_TOKEN` and redeploy once Cloudflare-to-OpenOrange " +
          "migration cutover is complete.",
        [httpEvidence(`POST ${pathOf(url)}`, res, { method: "POST", body: excerpt(res.body, 300) })],
      ),
    ];
  },
});

registerProbe({
  id: "WF-DAST-RIVET-04",
  title: "RivetKit Prometheus metrics endpoint exposed",
  severity: "medium",
  probe: "W-RUN-*",
  family: "DAST",
  async check(ctx) {
    const findings: Finding[] = [];
    for (const base of engineBases(ctx)) {
      const url = `${base}/metrics`;
      let res: ProbeResponse;
      try {
        res = await ctx.http.request({ url });
      } catch {
        continue;
      }
      if (res.status !== 200) continue;
      if (!/rivet_rivetkit_actor_(?:active_count|http_requests_active|inbox_depth)/.test(res.body)) {
        continue;
      }
      findings.push(
        probeFinding(
          this,
          url,
          `GET ${pathOf(url)} serves RivetKit Prometheus metrics (\`rivet_rivetkit_actor_*\`), disclosing ` +
            "deployed Durable Object / Rivet Actor names, active counts, and request volume. Per OpenOrange's " +
            "monitoring docs, `RIVETKIT_METRICS_PORT` is intended to be scraped only from localhost/sidecar.",
          "Bind the metrics listener to `127.0.0.1` only (do not reverse-proxy `/metrics` publicly) and scrape " +
            "from an in-pod sidecar or authenticated internal network.",
          [httpEvidence("GET /metrics", res, { body: excerpt(res.body, 400) })],
        ),
      );
    }
    return findings;
  },
});
