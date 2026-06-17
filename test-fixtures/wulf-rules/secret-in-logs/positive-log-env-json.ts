const log = console;

export default {
  fetch(_req: Request, env: Record<string, unknown>) {
    // ruleid: wulf-secret-in-logs
    log.warn(JSON.stringify(env));
    return new Response("ok");
  },
};
