const sessions = new Map<string, string>();

export default {
  fetch(req: Request) {
    const url = new URL(req.url);
    const sid = url.searchParams.get("sid") ?? "missing";
    const token = req.headers.get("authorization") ?? "none";
    // ruleid: wulf-global-request-state
    sessions.set(sid, token);
    return Response.json({ size: sessions.size });
  },
};
