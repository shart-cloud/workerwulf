let lastRequestId = "none";

export default {
  fetch(req: Request) {
    const currentReqId = req.headers.get("cf-ray") ?? "local";
    // ruleid: wulf-global-request-state
    lastRequestId = currentReqId;
    return Response.json({ lastRequestId });
  },
};
