export default {
  fetch(_req: Request, _env: unknown, ctx: ExecutionContext) {
    // ok: wulf-passthrough-onexception
    ctx.waitUntil(Promise.resolve());
    return new Response("ok");
  },
};
