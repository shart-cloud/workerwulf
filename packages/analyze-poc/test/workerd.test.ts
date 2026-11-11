import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { SerializedReport } from "@wulf/analyze";
import { runScan } from "@wulf/cli/src/commands/scan.js";
import { cfApiFromPromises, collectAccount } from "@wulf/core";
import * as Effect from "effect/Effect";

import { FixtureAccount } from "./account-fixture.js";

import {
  cliDir,
  firstDiff,
  fixtureDirs,
  nativeParse,
  normalize,
  packagesDir,
  projectRequest,
  referenceAudit,
  rel,
  reportText,
  startWorkerd,
} from "./helpers.js";

// Runs the real Worker under `wrangler dev` (workerd), so this is the actual
// runtime, WASM loading and bundling, not a Node approximation.
let workerd: { url: string; stop: () => void };
beforeAll(async () => {
  workerd = await startWorkerd(8790 + Math.floor(Math.random() * 100));
}, 90_000);
afterAll(() => workerd?.stop());

const post = async (path: string, body: unknown) => {
  const res = await fetch(`${workerd.url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  expect(res.status).toBe(200);
  return res.json();
};

const fixtures = fixtureDirs();

describe("wulf rules inside workerd", () => {
  for (const dir of fixtures) {
    it(`matches \`wulf audit --source --json\` byte for byte for ${rel(dir)}`, async () => {
      const reference = referenceAudit(dir);
      const out = (await post("/analyze", projectRequest(dir, reference))) as { report: SerializedReport };
      expect(reportText(out.report)).toBe(reportText(reference));
      // Guard against a vacuous pass: the fixture set must exercise the rules.
      expect(reference.sources.length).toBeGreaterThan(0);
    });
  }

  it("fixtures produce findings at all", () => {
    const total = fixtures
      .map((d) => referenceAudit(d).sources.flatMap((s) => s.findings))
      .reduce((a, b) => [...a, ...b], []);
    console.log(`${fixtures.length} fixtures, ${total.length} reference findings`);
    expect(total.length).toBeGreaterThan(20);
    // Supply-chain rules read package.json, Dockerfiles and requirements.txt; they must be covered too.
    expect(total.filter((f) => f.rule_id.startsWith("WF-SC-")).length).toBeGreaterThan(0);
  });

  it("returns the same AST over HTTP as the native parser for every fixture source", async () => {
    const mismatches: string[] = [];
    for (const dir of fixtures) {
      for (const file of projectRequest(dir, referenceAudit(dir)).sources) {
        const native = normalize(nativeParse(file.path, file.text).program) as unknown;
        const remote = (await post("/parse", file)) as { program: unknown };
        const d = firstDiff(native, remote.program);
        if (d) mismatches.push(`${rel(dir)}/${file.path} ${d}`);
      }
    }
    expect(mismatches).toEqual([]);
  });

  it("parses a large real bundle (Effect's Schema.js) in workerd", async () => {
    const path = createRequire(join(packagesDir, "core", "package.json")).resolve("effect/Schema");
    const text = readFileSync(path, "utf8");
    const started = performance.now();
    const remote = (await post("/parse", { path: "bundle.js", text })) as { program: { body: unknown[] }; errors: string[] };
    const roundTrip = performance.now() - started;
    console.log(`Schema.js ${(text.length / 1024).toFixed(0)} KiB: ${remote.program.body.length} top-level statements, round trip ${roundTrip.toFixed(0)} ms`);
    expect(remote.errors).toEqual([]);
    expect(remote.program.body.length).toBeGreaterThan(100);
  });
});

describe("account rules inside workerd", () => {
  const deployedLocal = join(cliDir, "test", "fixtures", "deployed-local");

  it("matches `wulf scan --json` byte for byte on a collected snapshot", async () => {
    // The CLI collects from the fixture account itself and runs the rules in Node.
    const cli = await runScan({ accountId: "acct", json: true, source: deployedLocal }, new FixtureAccount());
    expect(cli.exitCode).toBe(0);
    const reference = JSON.parse(cli.output) as SerializedReport;

    // The Worker gets the same account as a snapshot, collected here by @wulf/core.
    const snapshot = await Effect.runPromise(
      collectAccount().pipe(Effect.provide(cfApiFromPromises("acct", new FixtureAccount()))),
    );
    const out = (await post("/scan", {
      snapshot,
      localSources: {
        prey: { path: "src/index.ts", text: readFileSync(join(deployedLocal, "src", "index.ts"), "utf8") },
      },
    })) as { report: SerializedReport; notes: string[] };

    expect(reportText(out.report)).toBe(reportText(reference));
    expect(out.notes).toEqual([]);

    // Every account rule fires, and both coverage gaps are reported.
    const ids = new Set(reference.sources.flatMap((s) => s.findings.map((f) => f.rule_id)));
    for (const id of ["WF-PRIV-01", "WF-PRIV-02", "WF-DRIFT-01", "WF-NS-01", "WF-NS-02", "WF-NS-03", "WF-NS-04"]) {
      expect(ids, id).toContain(id);
    }
    expect(reference.coverage?.map((c) => `${c.target} ${c.op} ${c.status}`)).toEqual([
      "script:locked bindings denied",
      "script:locked routes unavailable",
    ]);
  });

  it("rejects a malformed snapshot", async () => {
    const res = await fetch(`${workerd.url}/scan`, {
      method: "POST",
      body: JSON.stringify({ snapshot: { accountId: "acct", scripts: [{ bindings: "nope" }] } }),
    });
    expect(res.status).toBe(400);
  });
});
