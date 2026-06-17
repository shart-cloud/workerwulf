export default {
  async fetch(req: Request) {
    const token = req.headers.get("authorization") ?? "";
    // ruleid: wulf-sensitive-in-cache
    await caches.default.put(req, new Response(token));
    return new Response("ok");
  },
};
