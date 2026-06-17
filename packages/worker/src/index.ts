import type { ProbeResult } from "@wulf/shared";
import { probes } from "./probes/index.js";

export interface Env {
  PREY_KV: KVNamespace;
  PREY_R2: R2Bucket;
  LOGPUSH_R2: R2Bucket;
  PREY_D1: D1Database;
  SVC_SELF: Fetcher;
  SVC_RELAY: Fetcher;
  // Capability binding for W-CAP-01. Optional: present only once the
  // [[hyperdrive]] stanza is wired (post terraform apply). Absent locally.
  HYPERDRIVE?: Hyperdrive;
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
