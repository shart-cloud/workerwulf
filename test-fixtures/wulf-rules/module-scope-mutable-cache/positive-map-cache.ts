const cache = new Map<string, string>();

export default {
  fetch(req: Request) {
    const key = new URL(req.url).searchParams.get("key") ?? "default";
    // ruleid: wulf-module-scope-mutable-cache
    cache.set(key, Date.now().toString());
    return Response.json({ size: cache.size });
  },
};
