export default {
  fetch(req: Request) {
    const captured: string[] = [];
    const cfRay = req.headers.get("cf-ray") ?? "local";
    // ok: wulf-global-request-state
    captured.push(cfRay);
    return Response.json({ captured });
  },
};
