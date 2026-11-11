import { pathOf } from "../../dast/fingerprint.js";
import type { ProbeResponse } from "../../dast/http.js";
import { registerProbe, type Finding, type ProbeContext } from "../../engine/rule.js";
import { httpEvidence, probeFinding, sameOriginUrl } from "./_utils.js";

/** V8 stack frames, e.g. "at handle (index.js:42:17)" or "at worker.mjs:3:9". */
const STACK_FRAME = /\bat\s+(?:[\w$.<>[\] ]+\s+\()?[^\s()]*\.(?:m?js|ts|wasm)(?::\d+){1,2}\)?/;
const JS_ERROR = /\b(TypeError|ReferenceError|SyntaxError|URIError|RangeError|EvalError|AggregateError): [^\n<]{3,}/;
const UNCAUGHT_1101 = /Error 1101|Worker threw exception/i;

interface ErrorSample {
  res: ProbeResponse;
  method: string;
  body?: string;
}

/** Memoized per run so ERR-01 and ERR-02 share one set of POSTs. */
const samples = new WeakMap<ProbeContext, Promise<ErrorSample[]>>();

function errorResponses(ctx: ProbeContext): Promise<ErrorSample[]> {
  let p = samples.get(ctx);
  if (!p) {
    p = collectErrorSamples(ctx);
    samples.set(ctx, p);
  }
  return p;
}

async function collectErrorSamples(ctx: ProbeContext): Promise<ErrorSample[]> {
  const out: ErrorSample[] = ctx.fingerprint.error_probes.map((res) => ({ res, method: "GET" }));
  if (ctx.allowPost) {
    for (const path of ctx.paths) {
      const body = '{"wulf":';
      const res = await ctx.http.request({
        method: "POST",
        url: sameOriginUrl(ctx, path),
        headers: { "content-type": "application/json" },
        body,
      });
      out.push({ res, method: "POST", body });
    }
  }
  return out;
}

registerProbe({
  id: "WF-DAST-ERR-01",
  title: "Exception details / stack trace returned to client",
  severity: "medium",
  probe: "WF-FAIL-*",
  family: "DAST",
  async check(ctx) {
    const baselineLeaks = STACK_FRAME.test(ctx.fingerprint.baseline.body) || JS_ERROR.test(ctx.fingerprint.baseline.body);
    if (baselineLeaks) return []; // docs/blog page about errors — can't attribute
    const findings: Finding[] = [];
    for (const { res, method, body } of await errorResponses(ctx)) {
      if (res.status < 400) continue;
      const frame = res.body.match(STACK_FRAME)?.[0];
      const error = res.body.match(JS_ERROR)?.[0];
      if (!frame && !error) continue;
      findings.push(
        probeFinding(
          this,
          res.url,
          `Malformed input made the Worker return ${frame ? "a V8 stack trace" : "a raw JavaScript exception message"} (${(frame ?? error)!.slice(0, 120)}). This discloses bundle file names, line numbers and internal control flow.`,
          "Wrap the fetch handler in a top-level try/catch that logs the error server-side and returns a generic 500; never put `err.stack` or `err.message` in a Response.",
          [httpEvidence(`${method} ${pathOf(res.url)}`, res, { method, requestHeaders: body ? { "content-type": "application/json" } : undefined })],
        ),
      );
    }
    return findings;
  },
});

registerProbe({
  id: "WF-DAST-ERR-02",
  title: "Uncaught exception reachable from unauthenticated input (Error 1101)",
  severity: "low",
  probe: "WF-FAIL-*",
  family: "DAST",
  async check(ctx) {
    const findings: Finding[] = [];
    for (const { res, method } of await errorResponses(ctx)) {
      if (!UNCAUGHT_1101.test(res.body)) continue;
      findings.push(
        probeFinding(
          this,
          res.url,
          `${method} ${pathOf(res.url)} crashes the Worker (Cloudflare Error 1101). Unhandled throws abort the request mid-handler: any guard code after the throw never runs and any side effects before it are not rolled back, and the input reliably burns invocations.`,
          "Validate/decode input defensively (e.g. try/catch around decodeURIComponent and JSON.parse) and add a top-level error boundary to the fetch handler.",
          [httpEvidence(`${method} ${pathOf(res.url)}`, res, { method })],
        ),
      );
    }
    return findings;
  },
});
