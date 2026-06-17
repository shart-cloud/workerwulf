const memo: string[] = [];

export default {
  fetch(req: Request) {
    const path = new URL(req.url).pathname;
    // ruleid: wulf-module-scope-mutable-cache
    memo.push(path);
    return Response.json({ count: memo.length });
  },
};
