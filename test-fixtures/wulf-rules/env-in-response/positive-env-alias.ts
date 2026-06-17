export default {
  fetch(_req: Request, env: Record<string, unknown>) {
    const bindings = env;
    // ruleid: wulf-env-in-response
    return Response.json(bindings);
  },
};
