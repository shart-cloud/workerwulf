export interface Env {
  OUTBOUND_LOG?: R2Bucket;
  WULF_OUTBOUND_ALLOWLIST?: string;
  WULF_OUTBOUND_AUTH_TOKEN?: string;
  customer_name?: string;
  url?: string;
  run_id?: string;
  test_id?: string;
  [key: string]: unknown;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const started = Date.now();
    const url = new URL(req.url);
    const allowed = allowlist(env).some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`));
    const event = {
      timestamp: new Date().toISOString(),
      customer_name: env.customer_name ?? "unknown",
      run_id: env.run_id ?? null,
      test_id: env.test_id ?? null,
      original_url: env.url ?? null,
      outbound_url: req.url,
      hostname: url.hostname,
      allowed,
      method: req.method,
    };

    await writeLog(env, event);

    if (!allowed) {
      return new Response(JSON.stringify({ ok: false, blocked_by: "wulf-outbound", event }), {
        status: 403,
        headers: { "content-type": "application/json" },
      });
    }

    const outboundReq = withInjectedAuth(req, env.WULF_OUTBOUND_AUTH_TOKEN);
    const res = await fetch(outboundReq);
    await writeLog(env, { ...event, completed_ms: Date.now() - started, status: res.status });
    return res;
  },
};

function allowlist(env: Env): string[] {
  return (env.WULF_OUTBOUND_ALLOWLIST ?? "cloudflare.com")
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
}

function withInjectedAuth(req: Request, token: string | undefined): Request {
  if (!token) return req;
  const headers = new Headers(req.headers);
  headers.set("authorization", `Bearer ${token}`);
  return new Request(req, { headers });
}

async function writeLog(env: Env, event: Record<string, unknown>): Promise<void> {
  if (!env.OUTBOUND_LOG) return;
  const key = `outbound/${event.test_id ?? "unknown"}/${event.run_id ?? "unknown"}/${Date.now()}-${crypto.randomUUID()}.json`;
  await env.OUTBOUND_LOG.put(key, JSON.stringify(event, null, 2), {
    httpMetadata: { contentType: "application/json" },
  });
}
