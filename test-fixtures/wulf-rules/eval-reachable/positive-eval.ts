export default {
  async fetch(req: Request) {
    const code = new URL(req.url).searchParams.get("code") ?? "";
    // ruleid: wulf-eval-reachable
    return new Response(String(eval(code)));
  },
};
