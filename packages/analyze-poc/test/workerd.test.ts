import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  firstDiff,
  fixtureDirs,
  FS_RULE,
  inputFor,
  nativeParse,
  normalize,
  packagesDir,
  referenceAudit,
  rel,
  startWorkerd,
  withoutFsRules,
  type Reference,
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
    it(`matches \`wulf audit --source --json\` for ${rel(dir)}`, async () => {
      const reference: Reference = referenceAudit(dir);
      const out = (await post("/analyze", inputFor(dir, reference))) as Reference;

      const fsFindings = reference.sources.flatMap((s) => s.findings).filter((f) => FS_RULE.test(f.rule_id));
      if (fsFindings.length > 0) {
        console.log(`${rel(dir)}: ${fsFindings.length} supply-chain finding(s) need file access, excluded`);
      }
      expect(withoutFsRules(out.sources)).toEqual(withoutFsRules(reference.sources));
      // Guard against a vacuous pass: the fixture set must exercise the rules.
      expect(reference.sources.length).toBeGreaterThan(0);
    });
  }

  it("fixtures produce findings at all", () => {
    const total = fixtures
      .map((d) => referenceAudit(d).sources.flatMap((s) => s.findings).length)
      .reduce((a, b) => a + b, 0);
    console.log(`${fixtures.length} fixtures, ${total} reference findings`);
    expect(total).toBeGreaterThan(20);
  });

  it("returns the same AST over HTTP as the native parser for every fixture source", async () => {
    const mismatches: string[] = [];
    for (const dir of fixtures) {
      for (const file of inputFor(dir, referenceAudit(dir)).files) {
        const native = normalize(nativeParse(file.path, file.text).program) as { sourceType?: { variant?: string } };
        const remote = (await post("/parse", file)) as { program: { sourceType?: { variant?: string } } };
        delete native.sourceType?.variant;
        delete remote.program.sourceType?.variant;
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
