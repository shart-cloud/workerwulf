export default {
  fetch(req: Request) {
    const userId = new URL(req.url).searchParams.get("user") ?? "anonymous";
    // ok: wulf-secret-in-logs
    console.log({ userId });
    return new Response("ok");
  },
};
