export default {
  async fetch() {
    try {
      throw new Error("boom");
    } catch (err) {
      const error = err as Error;
      // ruleid: wulf-error-in-response
      return new Response(error.stack);
    }
  },
};
