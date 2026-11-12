import { analyzeAccount, summarizeSnapshot, WORKER_PARSE_LIMIT_BYTES } from "@wulf/analyze";
import { collectAccount, findingKey } from "@wulf/core";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vitest";

import { cfApiFor } from "../src/workflow.js";
import {
  fixtureAccount,
  hubOf,
  runScan,
  SENTINEL_BUNDLE,
  SENTINEL_VALUE,
  setAccount,
  shape,
  type FakeAccount,
} from "./helpers.js";

const fixed = (): FakeAccount => {
  const account = fixtureAccount();
  // The fix for WF-PRIV-01: drop the unused KV binding.
  account.scripts["prey"]!.bindings = account.scripts["prey"]!.bindings!.filter((b) => b["name"] !== "UNUSED_KV");
  return account;
};

/**
 * Wait until a scan is in R2. `complete` sets an alarm for now, which miniflare
 * may already have run; running it again is a no-op.
 */
async function exported(hub: ReturnType<typeof hubOf>, scanId: string): Promise<void> {
  for (let i = 0; i < 50; i++) {
    await runDurableObjectAlarm(hub);
    if ((await hub.scan(scanId))?.exported_at) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${scanId} was never exported`);
}

describe("ScanWorkflow → ScanHub", () => {
  it("stores the same findings and coverage as analysing the snapshot in memory (wulf scan)", async () => {
    const accountId = "acct-equivalence";
    await setAccount(fixtureAccount());
    const result = await runScan(accountId, "scan-eq-1");
    expect(result.status).toBe("complete");

    const snapshot = await Effect.runPromise(Effect.provide(collectAccount(), cfApiFor(env, accountId)));
    const expected = analyzeAccount(snapshot, { severity: "informational" }).groups.flatMap((g) => g.findings);
    const stored = await hubOf(accountId).findings();

    expect(stored.map(shape).sort()).toEqual(expected.map(shape).sort());
    expect(stored.length).toBeGreaterThanOrEqual(4);
    expect(result.opened).toBe(stored.length);

    const occurrences = await hubOf(accountId).occurrences("scan-eq-1");
    const byKey = new Map(expected.map((f) => [findingKey(f), f]));
    for (const o of occurrences) {
      const f = byKey.get(o.finding_key)!;
      expect({ message: o.message, remediation: o.remediation, evidence: o.evidence }).toEqual({
        message: f.message,
        remediation: f.remediation,
        evidence: f.evidence ?? null,
      });
    }

    const scan = await hubOf(accountId).scan("scan-eq-1");
    expect(scan!.coverage).toEqual(summarizeSnapshot(snapshot).coverage);
    expect(scan!.coverage.filter((c) => c.status !== "complete").map((c) => `${c.target} ${c.op} ${c.status}`)).toEqual([
      "script:locked bindings denied",
      "script:locked routes unavailable",
    ]);
  });

  it("keeps finding identity across scans and resolves a finding once it is fixed", async () => {
    const accountId = "acct-lifecycle";
    const hub = hubOf(accountId);
    await setAccount(fixtureAccount());
    const first = await runScan(accountId, "scan-life-1");
    const before = await hub.findings("open");

    const second = await runScan(accountId, "scan-life-2");
    expect(second).toMatchObject({ status: "complete", opened: 0, reopened: 0, resolved: 0, seen: first.seen });
    const again = await hub.findings("open");
    expect(again.map((f) => [f.key, f.first_seen])).toEqual(before.map((f) => [f.key, f.first_seen]));
    expect(again.every((f) => f.last_scan_id === "scan-life-2")).toBe(true);

    await setAccount(fixed());
    const third = await runScan(accountId, "scan-life-3");
    expect(third).toMatchObject({ status: "complete", resolved: 1, opened: 0 });
    const resolved = await hub.findings("resolved");
    expect(resolved.map((f) => f.key)).toEqual(["WF-PRIV-01|script:prey:binding:UNUSED_KV"]);
    expect(resolved[0]!.resolved_at).not.toBeNull();

    await setAccount(fixtureAccount());
    const fourth = await runScan(accountId, "scan-life-4");
    expect(fourth).toMatchObject({ reopened: 1, resolved: 0 });
    expect(await hub.findings("resolved")).toEqual([]);
  });

  it("never resolves from a partial scan", async () => {
    const accountId = "acct-partial";
    await setAccount(fixtureAccount());
    await runScan(accountId, "scan-partial-1");

    // Fixed, but a script's content read fails outright (5xx after retries): the scan is partial.
    const account = fixed();
    account.scripts["locked"]!.fail = { ...account.scripts["locked"]!.fail, content: 500 };
    await setAccount(account);
    const result = await runScan(accountId, "scan-partial-2");
    expect(result).toMatchObject({ status: "partial", resolved: 0 });
    expect(await hubOf(accountId).findings("resolved")).toEqual([]);
  });

  it("keeps a script's findings open when a read they depend on is denied", async () => {
    const accountId = "acct-denied";
    await setAccount(fixtureAccount());
    await runScan(accountId, "scan-denied-1");

    // The KV binding is gone, but prey's bindings read is now denied: we can't tell.
    const account = fixed();
    account.scripts["prey"]!.fail = { settings: 403 };
    await setAccount(account);
    const result = await runScan(accountId, "scan-denied-2");
    expect(result.status).toBe("complete");
    expect(result.resolved).toBe(0);
    expect(result.kept).toBeGreaterThanOrEqual(2);
  });

  it("records a bundle over the in-Worker parse limit as coverage, and keeps its findings", async () => {
    const accountId = "acct-large";
    await setAccount(fixtureAccount());
    await runScan(accountId, "scan-large-1");

    const account = fixtureAccount();
    const pad = `/*${"x".repeat(WORKER_PARSE_LIMIT_BYTES)}*/\n`;
    account.scripts["prey"]!.content = pad + account.scripts["prey"]!.content!;
    await setAccount(account);
    const result = await runScan(accountId, "scan-large-2");
    const scan = await hubOf(accountId).scan("scan-large-2");
    expect(scan!.coverage).toContainEqual(
      expect.objectContaining({ target: "script:prey", op: "analyze", status: "unavailable" }),
    );
    // WF-PRIV-01 needs the parsed bundle, so it can't fire; it must not be resolved either.
    expect(result.resolved).toBe(0);
    expect((await hubOf(accountId).findings("open")).map((f) => f.key)).toContain(
      "WF-PRIV-01|script:prey:binding:UNUSED_KV",
    );
  });

  it("fails a scan whose script list is denied, and changes no finding", async () => {
    const accountId = "acct-failed";
    await setAccount(fixtureAccount());
    await runScan(accountId, "scan-failed-1");
    const before = await hubOf(accountId).findings();

    await setAccount({ scripts: {}, fail: { list: 403 } });
    const result = await runScan(accountId, "scan-failed-2");
    expect(result).toMatchObject({ status: "failed", seen: 0, resolved: 0 });
    expect(await hubOf(accountId).findings()).toEqual(before);
  });

  it("keeps a suppressed finding suppressed across scans", async () => {
    const accountId = "acct-suppress";
    const hub = hubOf(accountId);
    await setAccount(fixtureAccount());
    await runScan(accountId, "scan-supp-1");
    const key = "WF-PRIV-02|script:prey";
    expect((await hub.suppress(key, "behind Access"))!.state).toBe("suppressed");

    await runScan(accountId, "scan-supp-2");
    expect((await hub.findings("suppressed")).map((f) => [f.key, f.suppressed_reason])).toEqual([
      [key, "behind Access"],
    ]);
    expect((await hub.unsuppress(key))!.state).toBe("open");
  });
});

describe("ScanHub storage", () => {
  it("is idempotent: a retried begin, append or complete changes nothing", async () => {
    const hub = hubOf("acct-idempotent");
    const batch = { scripts: [], namespaces: [], coverage: [{ target: "account", op: "listScripts", status: "complete" as const }] };
    await hub.begin("s1", "acct-idempotent", "2026-11-11T00:00:00.000Z", "test");
    await hub.begin("s1", "acct-idempotent", "2026-11-12T00:00:00.000Z", "test");
    expect(await hub.append("s1", 0, batch)).toBe(true);
    expect(await hub.append("s1", 0, { ...batch, coverage: [] })).toBe(true);
    const first = await hub.complete("s1", "2026-11-11T00:01:00.000Z");
    const second = await hub.complete("s1", "2026-11-11T00:09:00.000Z");
    expect(second).toEqual(first);
    expect(await hub.append("s1", 1, batch)).toBe(false);

    const scan = await hub.scan("s1");
    expect(scan).toMatchObject({ started_at: "2026-11-11T00:00:00.000Z", completed_at: "2026-11-11T00:01:00.000Z" });
    expect(scan!.coverage).toEqual(batch.coverage);
  });

  it("never persists binding values or bundle text, in SQLite or R2", async () => {
    const accountId = "acct-sentinel";
    const hub = hubOf(accountId);
    await setAccount(fixtureAccount());
    await runScan(accountId, "scan-sentinel-1");

    const tables = await runInDurableObject(hub, (_instance, state) => {
      const names = state.storage.sql
        .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\_cf\_%' ESCAPE '\\'")
        .toArray()
        .map((r) => r.name);
      return names.map((n) => JSON.stringify(state.storage.sql.exec(`SELECT * FROM "${n}"`).toArray())).join("\n");
    });
    expect(tables).toContain("UNUSED_KV");
    expect(tables).not.toContain(SENTINEL_VALUE);
    expect(tables).not.toContain(SENTINEL_BUNDLE);

    await exported(hub, "scan-sentinel-1");
    const listed = await env.HISTORY.list({ prefix: "history/scan-sentinel-1/" });
    expect(listed.objects.map((o) => o.key.split("/").pop()).sort()).toEqual([
      "coverage.jsonl",
      "edges.jsonl",
      "findings.jsonl",
      "observations.jsonl",
      "scan.json",
    ]);
    for (const o of listed.objects) {
      const text = await (await env.HISTORY.get(o.key))!.text();
      expect(text).not.toContain(SENTINEL_VALUE);
      expect(text).not.toContain(SENTINEL_BUNDLE);
    }
    const findings = (await (await env.HISTORY.get("history/scan-sentinel-1/findings.jsonl"))!.text())
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { key: string; message: string });
    expect(findings.map((f) => f.key).sort()).toEqual((await hub.findings()).map((f) => f.key).sort());
  });

  it("exports to R2 from the alarm, then prunes batches and old scan detail", async () => {
    const accountId = "acct-prune";
    const hub = hubOf(accountId);
    await setAccount(fixtureAccount());
    for (const n of [1, 2, 3]) await runScan(accountId, `scan-prune-${n}`);
    for (const n of [1, 2, 3]) await exported(hub, `scan-prune-${n}`);

    const counts = await runInDurableObject(hub, (_i, state) => {
      const count = (sql: string) => state.storage.sql.exec<{ n: number }>(sql).one().n;
      return {
        batches: count("SELECT COUNT(*) AS n FROM batches"),
        observedScans: count("SELECT COUNT(DISTINCT scan_id) AS n FROM observations"),
        unexported: count("SELECT COUNT(*) AS n FROM scans WHERE exported_at IS NULL"),
      };
    });
    // KEEP_SCANS is 2 in tests.
    expect(counts).toEqual({ batches: 0, observedScans: 2, unexported: 0 });
    for (const n of [1, 2, 3]) {
      expect(await env.HISTORY.head(`history/scan-prune-${n}/findings.jsonl`)).not.toBeNull();
    }
    // Every finding keeps its latest occurrence.
    expect((await hub.occurrences("scan-prune-3")).length).toBe((await hub.findings()).length);
  });
});

describe("HTTP", () => {
  const call = (path: string, init: RequestInit = {}, token = "hub-test-token") =>
    exports.default.fetch(
      new Request(`https://hub.test${path}`, {
        ...init,
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers },
      }),
    );

  it("refuses requests without the bearer token", async () => {
    expect((await call("/findings", {}, "wrong")).status).toBe(401);
    expect((await exports.default.fetch(new Request("https://hub.test/health"))).status).toBe(401);
    expect((await call("/health")).status).toBe(200);
  });

  it("ingests a pushed CLI scan and serves its findings", async () => {
    await setAccount(fixtureAccount());
    const snapshot = await Effect.runPromise(Effect.provide(collectAccount(), cfApiFor(env, "acct-test")));
    const summary = summarizeSnapshot(snapshot);
    const pushed = await call("/ingest/scan", {
      method: "POST",
      body: JSON.stringify({
        accountId: "acct-test",
        startedAt: "2026-11-11T00:00:00.000Z",
        batches: [{ scripts: summary.scripts, namespaces: summary.namespaces, coverage: summary.coverage }],
      }),
    });
    expect(pushed.status).toBe(200);
    const result = (await pushed.json()) as { status: string; opened: number };
    expect(result.status).toBe("complete");

    const findings = (await (await call("/findings?state=open")).json()) as Array<{ key: string }>;
    const expected = analyzeAccount(snapshot, { severity: "informational" }).groups.flatMap((g) => g.findings);
    expect(findings.map((f) => f.key).sort()).toEqual(expected.map(findingKey).sort());

    const other = await call("/ingest/scan", {
      method: "POST",
      body: JSON.stringify({ accountId: "someone-else", startedAt: "x", batches: [] }),
    });
    expect(other.status).toBe(403);

    const invalid = await call("/ingest/scan", {
      method: "POST",
      body: JSON.stringify({ accountId: "acct-test", startedAt: "x", batches: [{ scripts: "nope" }] }),
    });
    expect(invalid.status).toBe(400);
  });
});
