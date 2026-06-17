export default {
  async fetch(req: Request) {
    // ruleid: wulf-unbounded-body-read
    const body = await req.json();
    return Response.json(body);
  },
};
