const allowedMethods = ["GET", "POST"];

export default {
  fetch(req: Request) {
    // ok: wulf-global-request-state
    return new Response(String(allowedMethods.includes(req.method)));
  },
};
