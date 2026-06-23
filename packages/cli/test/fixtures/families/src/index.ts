// Family A — hardcoded secret (WF-SEC-01)
const BAKED_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Family C — module-scope mutable state (WF-STATE-01, WF-STATE-02)
let requestCount = 0;
const cache = new Map();

async function guardedScan(body: string): Promise<{ decision: string }> {
  try {
    // Family E — guard call whose catch swallows (WF-FAIL-03)
    validateInput(body);
    return { decision: "block" };
  } catch (err) {
    console.error("scan error", err);
  }
  // Family E — catch returns success value (WF-FAIL-01)
  try {
    return runScanner(body);
  } catch (e) {
    return { decision: "allow" };
  }
}

function validateInput(_body: string): void {
  // Family E — empty catch (WF-FAIL-02)
  try {
    JSON.parse(_body);
  } catch (e) {}
}

function runScanner(_body: string): { decision: string } {
  // Family B — eval, new Function, string setTimeout, dynamic import
  eval(_body); // WF-INJ-01
  const fn = new Function("return 1"); // WF-INJ-02
  setTimeout("doWork()", 100); // WF-INJ-03
  void import(_body); // WF-INJ-04
  return { decision: fn() ? "allow" : "block" };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    requestCount++;
    cache.set("last", Date.now());

    // Family D — Math.random in a security context (WF-CRYPTO-02)
    const sessionToken = Math.random().toString(36).slice(2);

    // Family D — timing-unsafe comparison of a secret (WF-CRYPTO-01)
    const provided = request.headers.get("x-api-key") ?? "";
    if (env.API_SECRET === provided) {
      // Family A — secret logged (WF-SEC-02)
      console.log("authed with", env.API_SECRET);
    }

    // Family G — Hyperdrive connectionString exposure (WF-BUSE-01)
    const conn = env.HYPERDRIVE.connectionString;

    // Family F — fetch in a loop without a signal (WF-RES-01)
    const urls = ["a", "b", "c"];
    for (const u of urls) {
      await fetch(u);
    }

    // Family F — SQL via template interpolation (WF-RES-02)
    const id = new URL(request.url).searchParams.get("id");
    await env.DB.prepare(`SELECT * FROM items WHERE id = ${id}`).run();

    // Family G — SQL via string concatenation (WF-BUSE-04)
    await env.DB.prepare("DELETE FROM items WHERE k = " + id).run();

    // Family G — service-binding SSRF (WF-BUSE-03)
    await env.SVC.fetch(request.url);

    // Family G — browser SSRF (WF-BUSE-02)
    const browser = await puppeteer.launch(env.BROWSER);
    const page = await browser.newPage();
    await page.goto(request.url);

    const verdict = await guardedScan(await request.text());

    // Family A — secret returned in response (WF-SEC-03)
    return new Response(JSON.stringify({ verdict, sessionToken, conn, secret: env.API_SECRET, BAKED_TOKEN }));
  },
};

declare const puppeteer: { launch(b: unknown): Promise<{ newPage(): Promise<{ goto(u: string): Promise<void> }> }> };

interface Env {
  HYPERDRIVE: { connectionString: string };
  BROWSER: unknown;
  API_SECRET: string;
  SVC: { fetch(input: string): Promise<Response> };
  DB: { prepare(q: string): { run(): Promise<unknown> } };
}
