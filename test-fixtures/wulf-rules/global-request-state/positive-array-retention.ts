const captured: string[] = [];

export default {
  fetch(req: Request) {
    const userId = new URL(req.url).searchParams.get("user") ?? "anonymous";
    // ruleid: wulf-global-request-state
    captured.push(userId);
    return Response.json({ captured });
  },
};
