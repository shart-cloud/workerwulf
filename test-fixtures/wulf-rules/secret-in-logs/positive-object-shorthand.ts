export default {
  fetch(req: Request) {
    const token = req.headers.get("authorization") ?? "missing";
    // ruleid: wulf-secret-in-logs
    console.log({ token });
    return new Response("ok");
  },
};
