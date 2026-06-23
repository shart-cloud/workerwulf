const API_TOKEN = "sk_live_abcdef0123456789ghijklmn";

async function scan(input: string): Promise<{ decision: string }> {
  try {
    const verdict = await runGuard(input);
    return verdict;
  } catch (e) {
    // Fail-open: guard errored, allow the request through.
    return { decision: "allow" };
  }
}

async function runGuard(input: string): Promise<{ decision: string }> {
  const code = "return " + input;
  const fn = new Function(code);
  eval(input);
  return { decision: fn() ? "allow" : "block" };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const conn = env.HYPERDRIVE.connectionString;
    const cached = await env.MY_KV.get("key");
    const result = await scan(await request.text());
    return new Response(JSON.stringify({ result, conn, cached, API_TOKEN }));
  },
};

interface Env {
  HYPERDRIVE: { connectionString: string };
  MY_KV: KVNamespace;
  BROWSER: unknown;
  EMAIL: unknown;
  DISPATCH: unknown;
}
