import { describe, expect, it } from "vitest";

import { runProbe, type ProbeOptions } from "../src/commands/probe.js";
import type { HttpClient, ProbeRequest, ProbeResponse, WsRequest, WsResult } from "../src/dast/http.js";
import { inScope, parseScope } from "../src/dast/scope.js";

/** Every run in this file disables request pacing so tests don't sleep. */
function probe(url: string, opts: ProbeOptions, client: HttpClient) {
  return runProbe(url, { rps: Infinity, ...opts }, client);
}

const CF_RAY = "8b2e1f0a1c2d3e4f-EWR";

function res(partial: Partial<ProbeResponse> & { url: string }): ProbeResponse {
  return {
    status: 200,
    headers: { server: "cloudflare", "cf-ray": CF_RAY },
    body: "",
    elapsed_ms: 1,
    ...partial,
  };
}

/** Programmable Worker: route table keyed by `METHOD path` (path incl. query). */
class FakeWorker implements HttpClient {
  readonly seen: ProbeRequest[] = [];
  constructor(private readonly handler: (req: ProbeRequest, url: URL) => Partial<ProbeResponse>) {}

  async request(req: ProbeRequest): Promise<ProbeResponse> {
    this.seen.push(req);
    const url = new URL(req.url);
    return res({ url: req.url, ...this.handler(req, url) });
  }
  async websocket(req: WsRequest): Promise<WsResult> {
    return { url: req.url, accepted: false, messages: [] };
  }
}

const ids = (output: string): string[] =>
  JSON.parse(output).sources.flatMap((s: { findings: { rule_id: string }[] }) => s.findings.map((f) => f.rule_id));

describe("scope matching", () => {
  it("matches exact hosts and leading-wildcard subdomains, honouring ports", () => {
    const s = parseScope(["app.example.com", "*.lab.example.com", "localhost:8787"]);
    expect(inScope(s, "https://app.example.com/x")).toBe(true);
    expect(inScope(s, "https://evil.example.com/")).toBe(false);
    expect(inScope(s, "https://a.lab.example.com/")).toBe(true);
    expect(inScope(s, "https://lab.example.com/")).toBe(false); // apex excluded by *.
    expect(inScope(s, "http://localhost:8787/")).toBe(true);
    expect(inScope(s, "http://localhost:9999/")).toBe(false); // wrong port
  });
});

describe("wulf probe — scope gate", () => {
  it("allows the target host implicitly and sends requests", async () => {
    const worker = new FakeWorker(() => ({ body: "hi" }));
    const { exitCode } = await probe("https://app.example.com/", { json: true }, worker);
    expect(exitCode).toBe(0);
    expect(worker.seen.length).toBeGreaterThan(0);
    // Every request the scanner sent stayed on the target origin.
    expect(worker.seen.every((r) => new URL(r.url).host === "app.example.com")).toBe(true);
  });
});

describe("wulf probe — fingerprint", () => {
  it("identifies a workers.dev host as cloudflare-workers with high confidence", async () => {
    const worker = new FakeWorker((_r, url) =>
      url.pathname === "/cdn-cgi/trace" ? { body: `colo=EWR\n` } : { body: "<!doctype html><h1>app</h1>" },
    );
    const { output } = await probe("https://demo.jg.workers.dev/", { json: true }, worker);
    const fp = JSON.parse(output).sources[0].findings.find((f: { rule_id: string }) => f.rule_id === "WF-DAST-FP-01");
    expect(fp.message).toMatch(/cloudflare-workers \(high confidence\)/);
  });

  it("identifies a self-hosted celld node from its reserved health path", async () => {
    const worker = new FakeWorker((_r, url): Partial<ProbeResponse> => {
      if (url.pathname === "/.well-known/celld/health") return { status: 200, body: '{"ok":true}', headers: {} };
      return { headers: {}, body: "<h1>app on celld</h1>" }; // no cloudflare edge headers
    });
    const { output } = await probe("https://cell.example.com/", { json: true, allow: "cell.example.com" }, worker);
    const fp = JSON.parse(output).sources[0].findings.find((f: { rule_id: string }) => f.rule_id === "WF-DAST-FP-01");
    expect(fp.message).toMatch(/Platform: celld \(high confidence\)/);
  });

  it("flags a proxied origin (leaked origin server token) as not a Worker", async () => {
    const worker = new FakeWorker(() => ({
      headers: { server: "cloudflare", "cf-ray": CF_RAY, "cf-cache-status": "DYNAMIC", via: "1.1 nginx" },
      body: "<html>wp</html>",
    }));
    const { output } = await probe("https://blog.example.com/", { json: true, allow: "blog.example.com" }, worker);
    const fp = JSON.parse(output).sources[0].findings.find((f: { rule_id: string }) => f.rule_id === "WF-DAST-FP-01");
    expect(fp.message).toMatch(/cloudflare-proxied-origin/);
  });
});

describe("wulf probe — exposure", () => {
  it("flags a .dev.vars secrets file and redacts its values", async () => {
    const worker = new FakeWorker((_r, url) => {
      if (url.pathname === "/.dev.vars") return { body: "API_TOKEN=supersecret-value-123\nDB_URL=postgres://u:p@h/db" };
      if (url.pathname.startsWith("/wulf-")) return { status: 404, body: "not found" };
      return { body: "ok" };
    });
    const { output } = await probe("https://app.example.com/", { json: true, allow: "app.example.com" }, worker);
    const findings = JSON.parse(output).sources[0].findings;
    const leak = findings.find((f: { rule_id: string }) => f.rule_id === "WF-DAST-EXPOSE-01");
    expect(leak.severity).toBe("critical");
    const inline = leak.evidence.map((e: { inline: string }) => e.inline).join("\n");
    expect(inline).not.toContain("supersecret-value-123");
    expect(inline).toMatch(/API_TOKEN=<redacted \d+ chars>/);
  });

  it("does not flag secrets on a catch-all SPA that 200s every path", async () => {
    const worker = new FakeWorker(() => ({ body: "<!doctype html><div id=root></div>", headers: { server: "cloudflare", "cf-ray": CF_RAY, "content-type": "text/html" } }));
    const { output } = await probe("https://spa.example.com/", { json: true, allow: "spa.example.com" }, worker);
    expect(ids(output)).not.toContain("WF-DAST-EXPOSE-01");
  });
});

describe("wulf probe — error disclosure", () => {
  it("flags a stack trace returned from malformed input", async () => {
    const worker = new FakeWorker((_r, url) => {
      if (url.search.includes("%E0%A4%A") || url.pathname.includes("%E0%A4%A")) {
        return { status: 500, body: "URIError: URI malformed\n    at handle (worker.js:42:17)\n    at fetch (worker.js:10:3)" };
      }
      return { body: "ok" };
    });
    const { output } = await probe("https://api.example.com/", { json: true, allow: "api.example.com" }, worker);
    expect(ids(output)).toContain("WF-DAST-ERR-01");
  });
});

describe("wulf probe — CORS", () => {
  it("flags reflected Origin with credentials as high", async () => {
    const worker = new FakeWorker((req) => {
      const origin = req.headers?.["origin"];
      return origin && origin !== "null"
        ? { headers: { server: "cloudflare", "cf-ray": CF_RAY, "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } }
        : { body: "ok" };
    });
    const { output } = await probe("https://api.example.com/", { json: true, allow: "api.example.com" }, worker);
    const cors = JSON.parse(output).sources[0].findings.find((f: { rule_id: string }) => f.rule_id === "WF-DAST-CORS-01");
    expect(cors.severity).toBe("high");
  });
});

describe("wulf probe — celld operator exposure", () => {
  const NODE_STATE = JSON.stringify({
    ownership: "owner",
    owned_cells: 3,
    occupied: true,
    residents: ["counter:main"],
    published: [],
    rss_bytes: 1234,
    node_load: 0.2,
    deployment: { version: "v7", prefix: "p", generation: 4 },
  });

  it("flags an unauthenticated /state on an explicit internal listener as critical", async () => {
    const worker = new FakeWorker((_r, url) => {
      if (url.port === "9000" && url.pathname === "/state") return { status: 200, headers: { "content-type": "application/json" }, body: NODE_STATE };
      return { body: "ok" };
    });
    const { output } = await probe(
      "https://node.example.com/",
      { json: true, allow: "node.example.com", celldInternal: "https://node.example.com:9000" },
      worker,
    );
    const f = JSON.parse(output).sources[0].findings.find((x: { rule_id: string }) => x.rule_id === "WF-DAST-CELLD-01");
    expect(f.severity).toBe("critical");
    expect(f.message).toMatch(/version v7/);
    expect(f.message).toMatch(/destructive routes were not invoked/);
  });

  it("detects a merged public+operator listener when the target itself is celld", async () => {
    const worker = new FakeWorker((_r, url): Partial<ProbeResponse> => {
      if (url.pathname === "/.well-known/celld/health") return { status: 200, headers: {}, body: '{"ok":true}' };
      if (url.pathname === "/state") return { status: 200, headers: { "content-type": "application/json" }, body: NODE_STATE };
      return { headers: {}, body: "app" };
    });
    const { output } = await probe("https://cell.example.com/", { json: true, allow: "cell.example.com" }, worker);
    const f = JSON.parse(output).sources[0].findings.find((x: { rule_id: string }) => x.rule_id === "WF-DAST-CELLD-01");
    expect(f.message).toMatch(/merged or the internal one is internet-reachable/);
  });

  it("does not probe /state on a plain Cloudflare target", async () => {
    const worker = new FakeWorker((_r, url) => {
      if (url.pathname === "/state") return { status: 200, headers: { "content-type": "application/json" }, body: NODE_STATE };
      return { body: "ok" };
    });
    const { output } = await probe("https://api.example.com/", { json: true, allow: "api.example.com" }, worker);
    expect(ids(output)).not.toContain("WF-DAST-CELLD-01");
    // /state was never requested, because the target didn't fingerprint as celld.
    expect(worker.seen.some((r) => new URL(r.url).pathname === "/state")).toBe(false);
  });
});

describe("wulf probe — budget & passive", () => {
  it("passive mode sends only fingerprint requests and finds no vuln rules", async () => {
    const worker = new FakeWorker(() => ({ body: "ok" }));
    const { output } = await probe("https://app.example.com/", { json: true, allow: "app.example.com", passive: true }, worker);
    const found = ids(output);
    expect(found.every((id) => id === "WF-DAST-FP-01" || id === "WF-DAST-ACCESS-01")).toBe(true);
  });

  it("stops at the request budget", async () => {
    const worker = new FakeWorker(() => ({ body: "ok" }));
    const { output } = await runProbe(
      "https://app.example.com/",
      { json: false, allow: "app.example.com", maxRequests: 3, rps: Infinity },
      worker,
    );
    expect(output).toMatch(/budget of 3 exhausted/);
  });
});
