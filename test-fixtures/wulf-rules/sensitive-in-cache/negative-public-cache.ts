export default {
  async fetch(req: Request) {
    const body = "public asset";
    // ok: wulf-sensitive-in-cache
    await caches.default.put(req, new Response(body));
    return new Response(body);
  },
};
