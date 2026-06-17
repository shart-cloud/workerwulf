export default {
  fetch(_req: Request, env: { SERVICE_TOKEN: string }) {
    const apiUrl = "https://api.example.com/v1/messages";
    // ok: wulf-cf-api-token-in-worker
    return fetch(apiUrl, {
      headers: {
        Authorization: `Bearer ${env.SERVICE_TOKEN}`,
      },
    });
  },
};
