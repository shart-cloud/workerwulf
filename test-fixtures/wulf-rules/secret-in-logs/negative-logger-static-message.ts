const logger = console;

export default {
  fetch() {
    // ok: wulf-secret-in-logs
    logger.info("request started");
    return new Response("ok");
  },
};
