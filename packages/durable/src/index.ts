import type { ProbeResult } from "@wulf/shared";
import { PreyDurableObject } from "./durable/vulnerable.js";
import { PreyDurableObjectSecure } from "./durable/secure.js";
import { probes } from "./probes/index.js";

export { PreyDurableObject, PreyDurableObjectSecure };

export interface Env {
  PREY_DO: DurableObjectNamespace;
  PREY_DO_SECURE: DurableObjectNamespace;
  PREY_KV: KVNamespace;
  PREY_R2: R2Bucket;
  LOGPUSH_R2: R2Bucket;
  PREY_D1: D1Database;
  DYNAMIC_PARENT?: Fetcher;
  WULF_CALLBACK_HTTP_BASE?: string;
  WULF_DNS_EXFIL_ZONE?: string;
  WULF_DYNAMIC_BASE_URL?: string;
  // Shared secret gating /probes and /probe/* (F-003). Fail-closed when unset.
  WULF_AUTH_TOKEN?: string;
  [key: string]: unknown;
}

function authorized(req: Request, env: Env): boolean {
  const expected = env.WULF_AUTH_TOKEN;
  if (!expected) return false;
  const auth = req.headers.get("authorization") ?? "";
  const presented = auth.startsWith("Bearer ")
    ? auth.slice("Bearer ".length)
    : (req.headers.get("x-wulf-auth") ?? "");
  if (presented.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= presented.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/" || url.pathname === "/probes") {
      if (!authorized(req, env)) return json({ error: "unauthorized" }, 401);
      return json({ probes: Object.keys(probes) });
    }

    const match = url.pathname.match(/^\/probe\/([A-Z0-9-]+)$/);
    if (!match) return json({ error: "not_found" }, 404);
    if (!authorized(req, env)) return json({ error: "unauthorized" }, 401);

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
          message: err instanceof Error ? err.message : String(err),
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
