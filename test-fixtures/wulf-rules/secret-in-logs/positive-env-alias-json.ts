export default {
  fetch(_req: Request, env: Record<string, unknown>) {
    const secrets = env;
    // ruleid: wulf-secret-in-logs
    console.warn(JSON.stringify(secrets));
    return new Response("ok");
  },
};
