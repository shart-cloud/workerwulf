export default {
  fetch(_req: Request, env: { CF_API_TOKEN: string }) {
    const apiUrl = "https://api.cloudflare.com/client/v4/accounts/example/workers/scripts";
    // ruleid: wulf-cf-api-token-in-worker
    return fetch(apiUrl, {
      headers: {
        Authorization: `Bearer ${env.CF_API_TOKEN}`,
      },
    });
  },
};
