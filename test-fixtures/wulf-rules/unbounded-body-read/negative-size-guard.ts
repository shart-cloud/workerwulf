export default {
  async fetch(req: Request) {
    const len = Number(req.headers.get("content-length") ?? "0");
    if (len > 1024 * 1024) return new Response("too large", { status: 413 });
    // ok: wulf-unbounded-body-read
    const body = await req.text();
    return new Response(body);
  },
};
