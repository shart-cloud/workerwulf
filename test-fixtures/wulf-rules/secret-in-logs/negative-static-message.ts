export default {
  fetch() {
    // ok: wulf-secret-in-logs
    console.log("request started");
    return new Response("ok");
  },
};
