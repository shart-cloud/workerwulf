import { describe, expect, it } from "vitest";

import { auditProject, parseWranglerText } from "../src/index.js";

function audit(wranglerToml: string, code: string) {
  const parsed = parseWranglerText("wrangler.toml", wranglerToml);
  const res = auditProject({
    configPath: "wrangler.toml",
    config: parsed.config,
    sources: [{ path: "src/index.ts", text: code }],
  });
  return res.groups.flatMap((g) => g.findings);
}

describe("Wave 5 — Workers Cache rules (WF-WC-01..04)", () => {
  const cachedWrangler = `
name = "wc-app"
main = "src/index.ts"
compatibility_date = "2026-07-01"

[exports.WcVictim]
type = "worker"
[exports.WcVictim.cache]
enabled = true
cross_version_cache = true
`;

  it("flags enabled Workers Cache with cross_version_cache, purgeEverything, Set-Cookie stripping, and unkeyed identity headers", () => {
    const findings = audit(
      cachedWrangler,
      `
export default {
  async fetch(request, env, ctx) {
    const user = request.headers.get("x-user-id");
    if (request.url.endsWith("/purge")) {
      await ctx.cache.purge({ purgeEverything: true });
    }
    const res = new Response("secret for " + user);
    res.headers.delete("Set-Cookie");
    return res;
  },
};
`,
    );
    const ids = findings.map((f) => f.rule_id);
    expect(ids).toContain("WF-WC-01");
    expect(findings.find((f) => f.rule_id === "WF-WC-01")?.severity).toBe("high");
    expect(ids).toContain("WF-WC-02");
    expect(ids).toContain("WF-WC-03");
    expect(ids).toContain("WF-WC-04");
  });

  it("does not flag WF-WC-04 when ctx.props is used, nor WF-WC-02 for tag purges", () => {
    const findings = audit(
      `
name = "wc-safe"
main = "src/index.ts"
compatibility_date = "2026-07-01"

[exports.WcSafe]
type = "worker"
[exports.WcSafe.cache]
enabled = true
cross_version_cache = false
`,
      `
export default {
  async fetch(request, env, ctx) {
    const user = ctx.props.userId ?? request.headers.get("x-user-id");
    await ctx.cache.purge({ tags: ["user:" + user] });
    return new Response("hello " + user, { headers: { "cache-control": "private, no-store" } });
  },
};
`,
    );
    const ids = findings.map((f) => f.rule_id);
    expect(ids).toContain("WF-WC-01");
    expect(findings.find((f) => f.rule_id === "WF-WC-01")?.severity).toBe("medium");
    expect(ids).not.toContain("WF-WC-02");
    expect(ids).not.toContain("WF-WC-03");
    expect(ids).not.toContain("WF-WC-04");
  });
});

describe("Wave 6 — Cloudflare Containers exec() rules (WF-CTR-01..05)", () => {
  const containerWrangler = `
name = "ctr-app"
main = "src/index.ts"
compatibility_date = "2026-07-01"
workers_dev = true

[[containers]]
class_name = "CtrTarget"
image = "./Dockerfile"
`;

  it("flags workers_dev containers, dynamic sh -c exec, non-numeric user, open internet start, tainted env, and tainted getTcpPort", () => {
    const findings = audit(
      containerWrangler,
      `
export class CtrTarget {
  async fetch(request) {
    const body = await request.json();
    await this.ctx.container.start();
    await this.ctx.container.exec(["sh", "-c", "echo " + body.cmd], {
      user: "nobody",
      env: body.env,
    });
    return this.ctx.container.getTcpPort(body.port).fetch(request);
  }
}
`,
    );
    const ids = findings.map((f) => f.rule_id);
    expect(ids).toContain("WF-CTR-01");
    expect(ids).toContain("WF-CTR-02");
    expect(ids).toContain("WF-CTR-03");
    expect(ids).toContain("WF-CTR-04");
    expect(ids).toContain("WF-CTR-05");
  });

  it("stays clean when workers_dev is false, argv is literal, numeric uid is used, internet is disabled, and port is constant", () => {
    const findings = audit(
      `
name = "ctr-safe"
main = "src/index.ts"
compatibility_date = "2026-07-01"
workers_dev = false

[[containers]]
class_name = "CtrTarget"
image = "./Dockerfile"
`,
      `
export class CtrTarget {
  async fetch(request) {
    const arg = new URL(request.url).searchParams.get("fmt") ?? "webp";
    await this.ctx.container.start({ enableInternet: false });
    await this.ctx.container.exec(["/usr/bin/ffmpeg", "-f", arg], {
      user: "65534",
      env: { LANG: "C" },
    });
    return this.ctx.container.getTcpPort(8080).fetch(request);
  }
}
`,
    );
    const ids = findings.map((f) => f.rule_id);
    expect(ids).not.toContain("WF-CTR-01");
    expect(ids).not.toContain("WF-CTR-02");
    expect(ids).not.toContain("WF-CTR-03");
    expect(ids).not.toContain("WF-CTR-04");
    expect(ids).not.toContain("WF-CTR-05");
  });
});
