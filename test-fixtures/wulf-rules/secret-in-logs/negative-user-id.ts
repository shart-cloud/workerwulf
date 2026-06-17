export default {
  fetch(req: Request) {
    const user_id = new URL(req.url).searchParams.get("user_id") ?? "anonymous";
    // ok: wulf-secret-in-logs
    console.log({ user_id });
    return new Response("ok");
  },
};
