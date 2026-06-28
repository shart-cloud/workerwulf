export default {
  fetch(): Response {
    return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*" } });
  },
};
