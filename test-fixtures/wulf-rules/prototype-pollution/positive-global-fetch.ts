export default {
  fetch() {
    // ruleid: wulf-prototype-pollution
    globalThis.fetch = async () => new Response("intercepted");
    return new Response("ok");
  },
};
