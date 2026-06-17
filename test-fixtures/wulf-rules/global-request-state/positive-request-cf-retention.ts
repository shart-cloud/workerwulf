let lastColo: unknown = null;

export default {
  fetch(req: Request) {
    const cf = req.cf;
    // ruleid: wulf-global-request-state
    lastColo = cf;
    return Response.json({ lastColo });
  },
};
