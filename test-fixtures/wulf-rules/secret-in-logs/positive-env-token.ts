export default {
  fetch(_req: Request, env: { API_TOKEN: string }) {
    // ruleid: wulf-secret-in-logs
    console.log(env.API_TOKEN);
    return new Response("ok");
  },
};
