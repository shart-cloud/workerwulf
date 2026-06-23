export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const value = await env.CACHE.get("greeting");
    return new Response(value ?? "hello");
  },
};

interface Env {
  CACHE: KVNamespace;
}
