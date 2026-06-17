export default {
  fetch(_req: Request, env: { API_KEY: string }) {
    const apiKey = env.API_KEY;
    // ruleid: wulf-secret-in-logs
    console.log(apiKey);
    return new Response("ok");
  },
};
