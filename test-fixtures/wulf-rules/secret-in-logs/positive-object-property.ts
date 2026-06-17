export default {
  fetch(req: Request) {
    const authToken = req.headers.get("authorization") ?? "missing";
    // ruleid: wulf-secret-in-logs
    console.error({ token: authToken });
    return new Response("ok");
  },
};
