let lastBody = "";

export default {
  async fetch(req: Request) {
    const body = await req.text();
    // ruleid: wulf-global-request-state
    lastBody = body;
    return Response.json({ lastBody });
  },
};
