const logger = console;

export default {
  fetch(req: Request) {
    const token = req.headers.get("authorization") ?? "missing";
    // ruleid: wulf-secret-in-logs
    logger.info(token);
    return new Response("ok");
  },
};
