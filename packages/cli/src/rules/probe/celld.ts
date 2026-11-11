import { pathOf } from "../../dast/fingerprint.js";
import type { ProbeResponse } from "../../dast/http.js";
import { registerProbe, type Finding, type ProbeContext } from "../../engine/rule.js";
import { excerpt, httpEvidence, probeFinding } from "./_utils.js";

/**
 * celld's internal listener serves an operator API whose core routes
 * (`/state`, `/cell/<scope>`, `/evict/<scope>`, `/do/<id>`, `POST /shutdown`)
 * take no authentication — the design relies entirely on that listener living
 * on a trusted private network (see celld docs/security.md). If the listener is
 * reachable from the internet, an unauthenticated attacker can read node state,
 * evict cells, address Durable Objects directly (bypassing the Worker), and
 * gracefully shut the node down.
 *
 * We confirm exposure with the one read-only route, `GET /state`, and never
 * touch the destructive ones (`/shutdown`, `/evict`, `/do`) — their exposure is
 * inferred, because they share the same unauthenticated listener.
 */

/** celld node-state JSON is a flat object with these distinctive keys. Alpha
 * can rename fields, so we require a quorum rather than an exact schema. */
const STATE_KEYS = ["ownership", "owned_cells", "residents", "published", "occupied", "rss_bytes", "node_load", "drainPins", "deployment"];

function looksLikeNodeState(res: ProbeResponse): boolean {
  if (res.status !== 200) return false;
  const ct = res.headers["content-type"] ?? "";
  if (ct && !/json|text\/plain/i.test(ct)) return false;
  let value: unknown;
  try {
    value = JSON.parse(res.body);
  } catch {
    return false;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const present = STATE_KEYS.filter((k) => k in (value as Record<string, unknown>));
  return present.length >= 3;
}

/** Pull the serving deployment version out of /state, if present — a useful IOC. */
function deploymentVersion(res: ProbeResponse): string | undefined {
  try {
    const v = JSON.parse(res.body) as { deployment?: { version?: unknown } };
    const ver = v.deployment?.version;
    return typeof ver === "string" || typeof ver === "number" ? String(ver) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Where to look for the operator API, in order:
 *  - an explicit --celld-internal address (the realistic "is my advertised
 *    internal listener reachable from outside?" check), and
 *  - the target origin itself, but only when the fingerprint already said
 *    celld — this catches an obsolete single-listener / merged-port setup
 *    without adding a /state request to every non-celld scan.
 */
function operatorBases(ctx: ProbeContext): string[] {
  const bases: string[] = [];
  if (ctx.celldInternal) bases.push(ctx.celldInternal.origin);
  if (ctx.fingerprint.platform === "celld") bases.push(ctx.target.origin);
  return [...new Set(bases)];
}

registerProbe({
  id: "WF-DAST-CELLD-01",
  title: "celld operator API exposed without authentication",
  severity: "critical",
  probe: "D-DO-*",
  family: "DAST",
  async check(ctx) {
    const findings: Finding[] = [];
    for (const base of operatorBases(ctx)) {
      const url = `${base}/state`;
      const res = await ctx.http.request({ url });
      if (!looksLikeNodeState(res)) continue;
      const version = deploymentVersion(res);
      const merged = base === ctx.target.origin;
      findings.push(
        probeFinding(
          this,
          url,
          `celld's unauthenticated operator API answers GET /state here${merged ? " on the public listener — the internal and public listeners appear merged or the internal one is internet-reachable" : ""}. ` +
            `Because every operator route shares this listener and none authenticates the caller, an attacker can also evict cells (/evict/<scope>), send requests straight to Durable Objects and bypass the Worker (/do/<id>), and shut the node down (POST /shutdown). ` +
            (version ? `Serving deployment version ${version}. ` : "") +
            "This check only called the read-only /state route; the destructive routes were not invoked.",
          "Bind the internal listener to loopback or a trusted overlay only (celld's --internal-listen defaults to 127.0.0.1). Never route the --advertise address to the public internet, keep it off the public listener's port, and put it behind WireGuard/Tailscale or a private-network firewall rule. See celld docs/security.md.",
          [httpEvidence("GET /state", res, { body: excerpt(res.body, 500) })],
        ),
      );
    }
    return findings;
  },
});

registerProbe({
  id: "WF-DAST-CELLD-02",
  title: "celld peer protocol port reachable",
  severity: "high",
  probe: "D-DO-*",
  family: "DAST",
  async check(ctx) {
    if (!ctx.celldInternal) return [];
    // /peer/probe is HMAC-gated, so an unauthenticated GET is rejected (401/403)
    // rather than served — but a *response from celld at all* (as opposed to a
    // connection refusal) proves the fleet's peer-transport port is reachable
    // from where we're scanning, which it must not be.
    const url = `${ctx.celldInternal.origin}/peer/probe`;
    let res: ProbeResponse;
    try {
      res = await ctx.http.request({ url, headers: { "x-cells-probe-challenge": `wulf-${ctx.nonce()}` } });
    } catch {
      return []; // connection refused / unreachable — the good outcome
    }
    // A 401/403 from celld (vs. a generic proxy/app 404) indicates the peer
    // endpoint is live. Only report when /state didn't already fire for this host.
    if (res.status !== 401 && res.status !== 403) return [];
    return [
      probeFinding(
        this,
        url,
        `The celld peer-protocol endpoint ${pathOf(url)} is reachable and rejected an unsigned request (HTTP ${res.status}) rather than refusing the connection. The peer transport carries replicated cell writes and tunneled RPC as plain, unencrypted HTTP; its establishment signature authenticates who may open a tunnel but does not encrypt or integrity-protect the bytes that follow.`,
        "Keep the internal listener on a private network and wrap it in an encrypted overlay (WireGuard/Tailscale) — celld terminates no TLS on either listener. Do not expose the peer port to untrusted networks.",
        [httpEvidence("GET /peer/probe (unsigned)", res)],
      ),
    ];
  },
});
