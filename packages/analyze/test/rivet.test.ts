import { describe, expect, it } from "vitest";

import {
  auditProject,
  parseWranglerText,
} from "../src/index.js";

function audit(wranglerToml: string, code: string) {
  const parsed = parseWranglerText("wrangler.toml", wranglerToml);
  const res = auditProject({
    configPath: "wrangler.toml",
    config: parsed.config,
    sources: [{ path: "src/index.ts", text: code }],
  });
  return res.groups.flatMap((g) => g.findings.map((f) => f.rule_id));
}

describe("Rivet / OpenOrange rules (WF-RIVET-01..06)", () => {
  it("flags embedded-token RIVET_ENDPOINT, RIVET_CLOUD_TOKEN, and ORANGE_MIGRATE_WORKER_URL in wrangler vars", () => {
    const ids = audit(
      `
name = "orange-app"
main = "src/index.ts"
compatibility_date = "2026-09-03"

[vars]
RIVET_ENDPOINT = "https://default:rivet_token.secret123@engine.example.com"
RIVET_CLOUD_TOKEN = "rcl_super_secret"
ORANGE_MIGRATE_WORKER_URL = "https://old.workers.dev"
`,
      `export default { fetch() { return new Response("ok"); } };`,
    );
    expect(ids).toContain("WF-RIVET-01");
    expect(ids).toContain("WF-RIVET-02");
  });

  it("does not flag a plain credential-free RIVET_ENDPOINT URL", () => {
    const ids = audit(
      `
name = "orange-app"
main = "src/index.ts"
compatibility_date = "2026-09-03"

[vars]
RIVET_ENDPOINT = "https://engine.internal:6420"
`,
      `export default { fetch() { return new Response("ok"); } };`,
    );
    expect(ids).not.toContain("WF-RIVET-01");
    expect(ids).not.toContain("WF-RIVET-02");
  });

  it("flags hardcoded Rivet tokens, Bearer default, subRequests: 0, broad mounts, omitted globalOutbound, and unauthenticated actors", () => {
    const ids = audit(
      `
name = "orange-app"
main = "src/index.ts"
compatibility_date = "2026-09-03"

[[worker_loaders]]
binding = "LOADER"
`,
      `
import { actor } from "rivetkit";

const adminAuth = "Bearer default";
const leaked = "rivet_token.abc1234567890";

export const counter = actor({
  state: { count: 0 },
  actions: {
    increment(c) { c.state.count += 1; return c.state.count; },
  },
});

export default {
  async fetch(req, env) {
    const w1 = env.LOADER.load({
      compatibilityDate: "2026-09-03",
      mainModule: "main.js",
      modules: { "main.js": "export default { fetch() { return new Response('hi'); } }" },
      limits: { subRequests: 0 },
      mounts: [{ guestPath: "/app", hostPath: "." }],
    });
    return w1.getEntrypoint().fetch(req);
  },
};
`,
    );
    expect(ids).toContain("WF-RIVET-03");
    expect(ids).toContain("WF-RIVET-04");
    expect(ids).toContain("WF-RIVET-05");
    expect(ids).toContain("WF-RIVET-06");
  });

  it("stays clean when globalOutbound is set, mounts are scoped, and actor has an auth hook", () => {
    const ids = audit(
      `
name = "orange-safe"
main = "src/index.ts"
compatibility_date = "2026-09-03"

[[worker_loaders]]
binding = "LOADER"
`,
      `
import { actor } from "rivetkit";

export const counter = actor({
  state: { count: 0 },
  onBeforeConnect(c, opts) {
    if (!opts.params?.token) throw new Error("unauthorized");
  },
  actions: {
    increment(c) { c.state.count += 1; return c.state.count; },
  },
});

export default {
  async fetch(req, env) {
    const w = env.LOADER.get("safe", () => ({
      compatibilityDate: "2026-09-03",
      mainModule: "main.js",
      modules: { "main.js": "export default { fetch() { return new Response('hi'); } }" },
      globalOutbound: null,
      mounts: [{ guestPath: "/app", hostPath: "dist/standalone" }],
      vmLimits: { heapMb: 256, cpuTimeMs: 5000 },
    }));
    return w.getEntrypoint().fetch(req);
  },
};
`,
    );
    expect(ids).not.toContain("WF-RIVET-03");
    expect(ids).not.toContain("WF-RIVET-04");
    expect(ids).not.toContain("WF-RIVET-05");
    expect(ids).not.toContain("WF-RIVET-06");
  });
});
