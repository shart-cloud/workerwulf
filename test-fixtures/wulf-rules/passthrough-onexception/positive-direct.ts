export default {
  fetch(_req: Request, _env: unknown, ctx: ExecutionContext) {
    // ruleid: wulf-passthrough-onexception
    ctx.passThroughOnException();
    throw new Error("origin fallback");
  },
};
