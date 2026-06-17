export default {
  async fetch() {
    try {
      throw new Error("boom");
    } catch (_err) {
      // ok: wulf-error-in-response
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
};
