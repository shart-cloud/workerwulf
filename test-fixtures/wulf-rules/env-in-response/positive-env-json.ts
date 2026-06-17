export default {
  fetch(_req: Request, env: Record<string, unknown>) {
    // ruleid: wulf-env-in-response
    return new Response(JSON.stringify(env));
  },
};
