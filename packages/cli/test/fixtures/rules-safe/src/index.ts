const ALLOWED = new Set(["https://example.com/next"]);

function allowlisted(value: string | null): string {
  if (value && ALLOWED.has(value)) return value;
  return "https://example.com/next";
}

function authorizeBatch(_batch: MessageBatch): boolean {
  return true;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const destination = allowlisted(url.searchParams.get("next"));

    await fetch("https://api.example.com/static");
    await caches.default.put(new Request("https://cache.example/static"), new Response("static"));
    await env.INTERNAL.fetch("https://internal.example/task", {
      headers: { "X-User-ID": "system" },
    });

    return Response.redirect(destination);
  },

  async queue(batch: MessageBatch, env: Env): Promise<void> {
    if (!authorizeBatch(batch)) return;
    await env.TASKS.send({ ok: true });
  },
};

interface Env {
  INTERNAL: Fetcher;
  TASKS: Queue;
}
