import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { PermissionDenied } from "@wulf/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runScan } from "../src/commands/scan.js";
import type { CfClient, RawBinding, RawNamespace } from "../src/cf/client.js";

const here = dirname(fileURLToPath(import.meta.url));
const deployedLocal = join(here, "fixtures", "deployed-local");

const DEPLOYED_CONTENT =
  "export default { fetch(req, env) { return new Response(env.HYPERDRIVE.connectionString); } };";

/** Canned Cloudflare account: one over-permissioned, publicly-routed script and
 * one trusted, wide-open WfP namespace. */
class FakeCfClient implements CfClient {
  async listScripts(): Promise<string[]> {
    return ["prey"];
  }
  async getScriptBindings(): Promise<RawBinding[]> {
    return [
      { type: "hyperdrive", name: "HYPERDRIVE" },
      { type: "kv_namespace", name: "UNUSED_KV" },
      { type: "plain_text", name: "GREETING" }, // non-capability — ignored
    ];
  }
  async getScriptContent(): Promise<string | undefined> {
    return DEPLOYED_CONTENT;
  }
  async getRoutes(): Promise<string[]> {
    return ["prey.example.com/*"];
  }
  async listNamespaces(): Promise<string[]> {
    return ["tenants"];
  }
  async getNamespace(name: string): Promise<RawNamespace | undefined> {
    return {
      name,
      trusted: true,
      outbound: undefined,
      limits: undefined,
      scripts: [{ name: "tenant-a", untrusted: false }],
    };
  }
}

const ruleIds = (output: string): string[] => {
  const parsed = JSON.parse(output);
  return parsed.sources.flatMap((s: { findings: { rule_id: string }[] }) =>
    s.findings.map((f) => f.rule_id),
  );
};

describe("wulf scan — account rules", () => {
  it("flags excess capability, public-route compound risk, and WfP posture", async () => {
    const { output } = await runScan(
      { accountId: "acct", json: true, source: deployedLocal },
      new FakeCfClient(),
    );
    const ids = ruleIds(output);
    // least-priv: UNUSED_KV declared but not referenced in deployed content
    expect(ids).toContain("WF-PRIV-01");
    // hyperdrive (high blast) on a publicly-routed script
    expect(ids).toContain("WF-PRIV-02");
    // drift: deployed content != local source
    expect(ids).toContain("WF-DRIFT-01");
    // WfP namespace posture
    expect(ids).toContain("WF-NS-01"); // trusted
    expect(ids).toContain("WF-NS-02"); // no outbound
    expect(ids).toContain("WF-NS-03"); // no limits
    expect(ids).toContain("WF-NS-04"); // scripts not untrusted
  });

  it("does not flag the referenced binding as excess", async () => {
    const { output } = await runScan({ accountId: "acct", json: true }, new FakeCfClient());
    const parsed = JSON.parse(output);
    const priv01 = parsed.sources
      .flatMap((s: { findings: { rule_id: string; resource: string }[] }) => s.findings)
      .filter((f: { rule_id: string }) => f.rule_id === "WF-PRIV-01");
    expect(priv01).toHaveLength(1);
    expect(priv01[0].resource).toContain("UNUSED_KV");
    expect(priv01[0].resource).not.toContain("HYPERDRIVE");
  });

  it("exits 1 under --strict when a high finding is present", async () => {
    const { exitCode } = await runScan(
      { accountId: "acct", strict: true },
      new FakeCfClient(),
    );
    expect(exitCode).toBe(1);
  });

  it("restricts to a single namespace with --namespace", async () => {
    const { output } = await runScan(
      { accountId: "acct", json: true, namespace: "tenants" },
      new FakeCfClient(),
    );
    expect(ruleIds(output)).toContain("WF-NS-01");
  });
});

describe("wulf scan — credentials", () => {
  let savedId: string | undefined;
  let savedToken: string | undefined;

  beforeEach(() => {
    savedId = process.env["CLOUDFLARE_ACCOUNT_ID"];
    savedToken = process.env["CLOUDFLARE_API_TOKEN"];
    delete process.env["CLOUDFLARE_ACCOUNT_ID"];
    delete process.env["CLOUDFLARE_API_TOKEN"];
  });
  afterEach(() => {
    if (savedId !== undefined) process.env["CLOUDFLARE_ACCOUNT_ID"] = savedId;
    if (savedToken !== undefined) process.env["CLOUDFLARE_API_TOKEN"] = savedToken;
  });

  it("errors with exit 2 when credentials are missing and no client is injected", async () => {
    const { exitCode, output } = await runScan({ json: false });
    expect(exitCode).toBe(2);
    expect(output).toContain("missing credentials");
  });
});

describe("wulf scan — coverage", () => {
  /** Same account, but the token can't read prey's settings. */
  class DeniedBindingsClient extends FakeCfClient {
    override async getScriptBindings(): Promise<RawBinding[]> {
      throw new PermissionDenied({ path: "/workers/scripts/prey/settings", status: 403 });
    }
  }

  it("reports a denied read as a coverage gap instead of passing silently", async () => {
    const { output } = await runScan({ accountId: "acct" }, new DeniedBindingsClient());
    expect(output).toContain("note: script:prey bindings: denied (HTTP 403");
    expect(output).toContain("binding and least-privilege rules ran on partial data");
  });

  it("adds the gaps to JSON output and keeps the rules that could still run", async () => {
    const { output } = await runScan({ accountId: "acct", json: true }, new DeniedBindingsClient());
    const parsed = JSON.parse(output);
    expect(parsed.coverage).toEqual([
      {
        target: "script:prey",
        op: "bindings",
        status: "denied",
        detail: "HTTP 403 on /workers/scripts/prey/settings",
      },
    ]);
    const ids = ruleIds(output);
    expect(ids).not.toContain("WF-PRIV-01"); // needs bindings
    expect(ids).toContain("WF-NS-01"); // namespace reads still complete
  });

  it("reports an empty coverage list when every read completed", async () => {
    const { output } = await runScan({ accountId: "acct", json: true }, new FakeCfClient());
    expect(JSON.parse(output).coverage).toEqual([]);
  });

  it("exits 2 with the reason when scripts can't be listed", async () => {
    class NoList extends FakeCfClient {
      override async listScripts(): Promise<string[]> {
        throw new PermissionDenied({ path: "/accounts/acct/workers/scripts", status: 403 });
      }
    }
    const { exitCode, output } = await runScan({ accountId: "acct" }, new NoList());
    expect(exitCode).toBe(2);
    expect(output).toBe(
      "error: cannot list Workers scripts: permission denied (HTTP 403) on /accounts/acct/workers/scripts",
    );
  });

  it("runs end to end over the REST layer with fetch", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      calls.push(url);
      const path = new URL(url).pathname.replace("/client/v4", "");
      const json = (result: unknown) => Response.json({ success: true, result });
      if (path === "/accounts/acct/workers/scripts") return json([{ id: "prey" }]);
      if (path.endsWith("/settings")) return json({ bindings: [{ type: "kv_namespace", name: "UNUSED_KV" }] });
      if (path.endsWith("/routes")) return new Response("", { status: 404 });
      if (path.endsWith("/content")) return new Response(DEPLOYED_CONTENT);
      if (path === "/accounts/acct/workers/dispatch/namespaces") return json([]);
      return new Response("unexpected", { status: 599 });
    });
    try {
      const { output, exitCode } = await runScan({ accountId: "acct", apiToken: "t", json: true });
      expect(exitCode).toBe(0);
      const parsed = JSON.parse(output);
      expect(ruleIds(output)).toContain("WF-PRIV-01");
      expect(parsed.coverage).toEqual([
        expect.objectContaining({ target: "script:prey", op: "routes", status: "unavailable" }),
      ]);
      expect(calls.every((u) => u.startsWith("https://api.cloudflare.com/client/v4/"))).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
