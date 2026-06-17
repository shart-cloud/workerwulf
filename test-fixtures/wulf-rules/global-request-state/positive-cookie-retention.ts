let lastCookie = "";

export default {
  fetch(req: Request) {
    const cookie = req.headers.get("cookie") ?? "none";
    // ruleid: wulf-global-request-state
    lastCookie = cookie;
    return Response.json({ lastCookie });
  },
};
