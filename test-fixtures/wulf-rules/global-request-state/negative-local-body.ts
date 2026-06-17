export default {
  async fetch(req: Request) {
    const body = await req.text();
    // ok: wulf-global-request-state
    return Response.json({ body });
  },
};
