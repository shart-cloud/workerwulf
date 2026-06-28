export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const target = url.searchParams.get("target");
    const body = await request.text();

    await fetch(request.url);
    const redirected = Response.redirect(target ?? "/");

    const copied = new Headers(request.headers);
    copied.set("x-reflected", request.headers.get("x-reflected") ?? "");
    copied.set("Access-Control-Allow-Origin", "*");

    await caches.default.put(request, new Response(body));
    await caches.default.put(new Request(url.searchParams.get("key") ?? "https://example.com"), new Response(env.API_SECRET));

    await env.INTERNAL.fetch(request);

    if (request.headers.get("x-internal-worker") === "worker-a") {
      await env.DB.prepare("select 1").all();
    }

    return new Response(await redirected.text(), {
      status: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "x-copy": request.headers.get("x-copy") ?? "",
      },
    });
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    await env.DB.prepare("delete from jobs where expired = 1").run();
  },

  async queue(_batch: MessageBatch, env: Env): Promise<void> {
    await env.BUCKET.put("queue-result", "ok");
  },
};

interface Env {
  DATA_KV: KVNamespace;
  BUCKET: R2Bucket;
  DB: D1Database;
  INTERNAL: Fetcher;
  API_SECRET: string;
  AI: unknown;
  BROWSER: unknown;
  TASKS: Queue;
}
