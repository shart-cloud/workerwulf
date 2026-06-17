export default {
  fetch() {
    const apiUrl = "https://api.cloudflare.com/client/v4/ips";
    // ok: wulf-cf-api-token-in-worker
    return fetch(apiUrl);
  },
};
