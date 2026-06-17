const cache: Record<string, string> = {};

export default {
  fetch(req: Request) {
    const key = new URL(req.url).searchParams.get("key") ?? "default";
    // ruleid: wulf-module-scope-mutable-cache
    cache[key] = "seen";
    return Response.json(cache);
  },
};
