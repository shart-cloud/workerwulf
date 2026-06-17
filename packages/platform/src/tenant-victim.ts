export interface Env {
  VICTIM_KV?: KVNamespace;
  VICTIM_SECRET?: string;
  [key: string]: unknown;
}

let victimMarker = `victim-${Math.random().toString(36).slice(2)}`;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const cmd = url.pathname.replace(/^\/cmd\/?/, "") || url.searchParams.get("cmd") || "health";

    try {
      if (cmd === "health") return json({ ok: true, tenant: "tenant-victim" });
      if (cmd === "init") return json(await init(env));
      if (cmd === "cache-write") return json(await cacheWrite(required(url, "key"), url.searchParams.get("value") ?? victimMarker));
      if (cmd === "cache-read") return json(await cacheRead(required(url, "key")));
      if (cmd === "secret") return json({ ok: true, secret: env.VICTIM_SECRET ?? null });
      if (cmd === "isolate-marker") return json({ own_marker: victimMarker, foreign_marker_observed: false });
      return json({ ok: false, error: "unknown_cmd", cmd }, 404);
    } catch (err) {
      return json({ ok: false, error: err instanceof Error ? err.message : String(err) }, 500);
    }
  },
};

async function init(env: Env): Promise<Record<string, unknown>> {
  await env.VICTIM_KV?.put("secret-doc", "flag{p-ten-03-kv-canary}");
  return { ok: true, seeded: Boolean(env.VICTIM_KV), victim_secret_present: Boolean(env.VICTIM_SECRET) };
}

async function cacheWrite(key: string, value: string): Promise<Record<string, unknown>> {
  await caches.default.put(new Request(key), new Response(value));
  return { ok: true, cache_key: key, wrote: true, value };
}

async function cacheRead(key: string): Promise<Record<string, unknown>> {
  const res = await caches.default.match(new Request(key));
  return { ok: true, cache_key: key, hit: Boolean(res), value: res ? await res.text() : null };
}

function required(url: URL, key: string): string {
  const value = url.searchParams.get(key);
  if (!value) throw new Error(`missing ${key}`);
  return value;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), { status, headers: { "content-type": "application/json" } });
}
