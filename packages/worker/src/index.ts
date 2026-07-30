import type { ProbeResult } from "@wulf/shared";
import type { BrowserWorker } from "@cloudflare/puppeteer";
import { probes } from "./probes/index.js";
import type { WcRegionDriver } from "./wc-region-driver.js";

// Wave 5 — the deliberately-vulnerable *cached* entrypoint (W-WC-* probes). Named
// export so it can be cached on its own via the Wrangler per-entrypoint `exports`
// map while the default /probe/* router below stays uncached.
export { WcVictim } from "./wc-victim.js";
// Wave 5 — multi-region driver for the cross-PoP half of W-WC-06/07. A DO is the
// only primitive that lets Worker code choose which data center it runs in.
export { WcRegionDriver } from "./wc-region-driver.js";

export interface Env {
  PREY_KV: KVNamespace;
  PREY_R2: R2Bucket;
  LOGPUSH_R2: R2Bucket;
  PREY_D1: D1Database;
  SVC_SELF: Fetcher;
  SVC_RELAY: Fetcher;
  // Wave 5 (W-WC-*) loopback to the cached WcVictim entrypoint. Optional: present
  // only once the [[services]] stanza is uncommented + the worker redeployed.
  SVC_WC_VICTIM?: Fetcher;
  // Wave 5 cross-PoP driver namespace (W-WC-06/07). Optional for the same reason:
  // present only once the DO stanza + migration are deployed.
  WC_REGION?: DurableObjectNamespace<WcRegionDriver>;
  // Wave 6 (W-CTR-*) — the wulf-container Worker, which wraps a container DO and
  // exposes ctx.container.exec() over a JSON-RPC surface. Optional: present only once
  // wulf-container is deployed and the [[services]] stanza is wired. `wrangler dev`
  // has no container runtime, so the whole family is deploy-only.
  SVC_CTR?: Fetcher;
  // Shared secret gating wulf-container's RPC surface. That Worker exposes an arbitrary
  // `sh -c` sink, so it is gated in code rather than by routing alone; both Workers hold
  // the same secret (`wrangler secret put WULF_CTR_AUTH`). Without it the W-CTR probes
  // report `blocked` rather than failing mid-run.
  WULF_CTR_AUTH?: string;
  // Capability bindings (W-CAP-*). Optional: present only once their stanzas
  // are wired + resources exist. Absent locally / pre-deploy.
  HYPERDRIVE?: Hyperdrive;
  VECTORIZE?: VectorizeIndex;
  BROWSER?: BrowserWorker;
  SEND_EMAIL?: SendEmail;
  // Wave 4 capability bindings (W-CAP-02/06/07/08).
  SECRET?: SecretsStoreSecret;
  PREY_QUEUE?: Queue;
  MTLS_FETCHER?: Fetcher;
  AE?: AnalyticsEngineDataset;
  AI?: Ai;
  // From/To for W-CAP-03. `to` must equal the binding's verified
  // destination_address; `from` must be on an Email-Routing-verified domain.
  WULF_EMAIL_FROM?: string;
  WULF_EMAIL_TO?: string;
  WULF_ENV_PROBE: string;
  WULF_CALLBACK_HTTP_BASE?: string;
  WULF_DNS_EXFIL_ZONE?: string;
  [key: string]: unknown;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/" || url.pathname === "/probes") {
      return json({ probes: Object.keys(probes) });
    }

    const match = url.pathname.match(/^\/probe\/([A-Z0-9-]+)$/);
    if (!match) return json({ error: "not_found" }, 404);

    const testId = match[1]!;
    const probe = probes[testId];
    if (!probe) return json({ error: "unknown_test_id", test_id: testId }, 404);

    const runId = url.searchParams.get("run_id") ?? crypto.randomUUID();

    try {
      const result = await probe({ env, ctx, req, runId });
      return json(result satisfies ProbeResult);
    } catch (err) {
      return json(
        {
          test_id: testId,
          error: "probe_threw",
          message: "Probe failed before it could return a structured result",
          error_name: err instanceof Error ? err.name : "unknown",
        },
        500,
      );
    }
  },
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}
