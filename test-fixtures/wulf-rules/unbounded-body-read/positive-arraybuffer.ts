export default {
  async fetch(req: Request) {
    // ruleid: wulf-unbounded-body-read
    const body = await req.arrayBuffer();
    return new Response(String(body.byteLength));
  },
};
