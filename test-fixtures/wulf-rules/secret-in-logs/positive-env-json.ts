export default {
  fetch(_req: Request, env: Record<string, unknown>) {
    // ruleid: wulf-secret-in-logs
    console.warn(JSON.stringify(env));
    return new Response("ok");
  },
};
