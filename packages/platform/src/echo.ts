// wulf-echo — a minimal header-reflecting upstream test fixture for P-CAP-03.
// Deployed on *.workers.dev (allowlisted by wulf-outbound), it echoes the request
// headers it received — including any Authorization the outbound Worker injected —
// so the probe can observe whether an operator-injected credential leaks back to a
// user Worker through a reflecting allowlisted upstream. Inert; logs nothing.
export default {
  async fetch(req: Request): Promise<Response> {
    const headers: Record<string, string> = {};
    for (const [k, v] of req.headers) headers[k] = v;
    return new Response(
      JSON.stringify({ ok: true, echo: true, method: req.method, url: req.url, headers }, null, 2),
      { headers: { "content-type": "application/json" } },
    );
  },
};
