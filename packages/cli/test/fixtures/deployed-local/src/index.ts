// Local source that intentionally differs from the deployed bundle (drift).
export default {
  async fetch(_request: Request, _env: Env): Promise<Response> {
    return new Response("local version, refactored — no connection string here");
  },
};

interface Env {
  HYPERDRIVE: { connectionString: string };
}
