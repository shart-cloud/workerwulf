import type { ProbeResult } from "@wulf/shared";
import { probes } from "./probes/index.js";

export interface Env {
  DISPATCHER: DispatchNamespace;
  DISPATCHER_TRUSTED?: DispatchNamespace;
  OUTBOUND_LOG?: R2Bucket;
  WULF_CALLBACK_HTTP_BASE?: string;
  WULF_DNS_EXFIL_ZONE?: string;
  WULF_ALLOWED_TEST_URL?: string;
  WULF_CAP03_UPSTREAM?: string;
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
          track: "platform",
          error: "probe_threw",
          message: err instanceof Error ? err.message : String(err),
        },
        500,
      );
    }
  },
};

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}
