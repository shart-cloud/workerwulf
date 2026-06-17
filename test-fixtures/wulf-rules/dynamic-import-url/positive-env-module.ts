export default {
  async fetch(_req: Request, env: { MODULE_URL: string }) {
    const moduleUrl = env.MODULE_URL;
    // ruleid: wulf-dynamic-import-url
    return Response.json(await import(moduleUrl));
  },
};
