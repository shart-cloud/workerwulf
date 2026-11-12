import type { AccountSnapshot } from "@wulf/core";
import { describe, expect, it } from "vitest";

import { accountContext, analyzeAccount, analyzeSummary, summarizeScript, summarizeSnapshot } from "../src/index.js";

const CONTENT = "export default { fetch(req, env) { return new Response(env.USED_KV + env.SECRET); } };";

const snapshot: AccountSnapshot = {
  accountId: "acct",
  scripts: [
    {
      name: "prey",
      bindings: [
        { type: "kv_namespace", name: "USED_KV", namespace_id: "kv1" },
        { type: "r2_bucket", name: "UNUSED_R2", bucket_name: "b" },
        { type: "plain_text", name: "GREETING", text: "binding-value" },
      ],
      routes: ["prey.example.com/*"],
      content: CONTENT,
    },
    { name: "bare" },
  ],
  namespaces: [],
  coverage: [{ target: "account", op: "listScripts", status: "complete" }],
};

describe("summaries", () => {
  it("keep binding names and usage, and drop bundle text and binding values", () => {
    const { summary, coverage } = summarizeScript(snapshot.scripts[0]!);
    expect(coverage).toEqual([]);
    expect(summary).toEqual({
      name: "prey",
      bindings: [
        { type: "kv_namespace", name: "USED_KV" },
        { type: "r2_bucket", name: "UNUSED_R2" },
        { type: "plain_text", name: "GREETING" },
      ],
      routes: ["prey.example.com/*"],
      contentLength: CONTENT.length,
      usage: { used: ["SECRET", "USED_KV"], envDestructured: false },
    });
    expect(JSON.stringify(summary)).not.toContain("binding-value");
    expect(summarizeScript(snapshot.scripts[1]!)).toEqual({ summary: { name: "bare" }, coverage: [] });
  });

  it("give the same findings as the snapshot they came from", () => {
    const direct = analyzeAccount(snapshot, { severity: "informational" });
    const viaJson = analyzeSummary(JSON.parse(JSON.stringify(summarizeSnapshot(snapshot))), {
      severity: "informational",
    });
    expect(viaJson).toEqual(direct);
    expect(direct.groups.flatMap((g) => g.findings.map((f) => f.rule_id))).toContain("WF-PRIV-01");
    // Drift rules still see the bundle when analysing in memory.
    expect(accountContext(snapshot).scripts[0]!.content).toBe(CONTENT);
  });

  it("record a bundle over the parse limit as analyze coverage instead of parsing it", () => {
    const { summary, coverage } = summarizeScript(snapshot.scripts[0]!, { maxParseLength: 10 });
    expect(summary.usage).toBeUndefined();
    expect(summary.contentLength).toBe(CONTENT.length);
    expect(coverage).toEqual([
      {
        target: "script:prey",
        op: "analyze",
        status: "unavailable",
        detail: `bundle is ${CONTENT.length} characters, over the 10 in-Worker parse limit`,
      },
    ]);
  });
});
