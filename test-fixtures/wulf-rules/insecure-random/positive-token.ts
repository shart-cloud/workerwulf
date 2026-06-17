export default {
  fetch() {
    // ruleid: wulf-insecure-random
    const sessionToken = Math.random().toString(36).slice(2);
    return new Response(sessionToken);
  },
};
