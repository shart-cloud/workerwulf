export default {
  async fetch(req: Request, env: { API_TOKEN: string }) {
    // ruleid: wulf-sensitive-in-cache
    await caches.default.put(req, new Response(env.API_TOKEN));
    return new Response("ok");
  },
};
