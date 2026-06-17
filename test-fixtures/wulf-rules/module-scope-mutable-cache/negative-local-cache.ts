export default {
  fetch(req: Request) {
    const localCache = new Map<string, string>();
    const key = new URL(req.url).searchParams.get("key") ?? "default";
    // ok: wulf-module-scope-mutable-cache
    localCache.set(key, "seen");
    return Response.json({ size: localCache.size });
  },
};
