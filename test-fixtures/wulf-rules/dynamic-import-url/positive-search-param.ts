export default {
  async fetch(req: Request) {
    const moduleUrl = new URL(req.url).searchParams.get("module") ?? "./safe.js";
    // ruleid: wulf-dynamic-import-url
    return Response.json(await import(moduleUrl));
  },
};
