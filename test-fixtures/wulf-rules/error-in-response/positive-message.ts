export default {
  async fetch() {
    try {
      throw new Error("boom");
    } catch (err) {
      // ruleid: wulf-error-in-response
      return new Response(String(err));
    }
  },
};
