import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";

import {
  buildBindingMap,
  calleeMemberPath,
  declaredBindings,
  findNodes,
  isMutableContainer,
  isStringConcat,
  isSuccessValue,
  isTimingUnsafeComparison,
  looksLikeSecret,
  parse,
  referencesRequestInput,
  secretBindingNames,
  templateHasExpressions,
} from "@wulf/analyze";

import { parseWrangler, resolveEnvironments } from "../src/parsers/wrangler.js";
import { runAudit } from "../src/commands/audit.js";

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = join(here, "fixtures", "vulnerable");
const clean = join(here, "fixtures", "clean");
const families = join(here, "fixtures", "families");
const rulesBad = join(here, "fixtures", "rules-bad");
const rulesSafe = join(here, "fixtures", "rules-safe");
const corsLow = join(here, "fixtures", "cors-low");

interface JsonFinding {
  rule_id: string;
  severity: string;
  resource: string;
}

interface JsonSource {
  source: string;
  findings: JsonFinding[];
}

const parsedSources = (output: string): JsonSource[] =>
  (JSON.parse(output) as { sources: JsonSource[] }).sources;

const allFindings = (output: string): JsonFinding[] =>
  parsedSources(output).flatMap((source) => source.findings);

const allRuleIds = (output: string): string[] => allFindings(output).map((f) => f.rule_id);

const firstOfType = (code: string, type: string) =>
  findNodes(parse("t.ts", code).ast, type)[0]!.node;

describe("wrangler parser + env resolution", () => {
  it("resolves [env.production] overrides on top of the base config", () => {
    const { config } = parseWrangler(join(vulnerable, "wrangler.toml"));
    const envs = resolveEnvironments(config);
    const prod = envs.find((e) => e.name === "production");
    expect(prod).toBeDefined();
    // inherited from base
    expect(prod!.config.main).toBe("src/index.ts");
    // env-specific
    expect(prod!.config["trusted_workers"]).toBe(true);
    expect(prod!.config.mtls_certificates?.[0]?.binding).toBe("CLIENT_CERT");
  });

  it("classifies declared bindings by type", () => {
    const { config } = parseWrangler(join(vulnerable, "wrangler.toml"));
    const types = declaredBindings(config).map((b) => b.type);
    expect(types).toContain("hyperdrive");
    expect(types).toContain("kv_namespace");
    expect(types).toContain("browser");
    expect(types).toContain("send_email");
    expect(types).toContain("dispatch_namespace");
  });
});

describe("binding map", () => {
  it("collects env.X references from a fetch handler", () => {
    const text = `export default { fetch(req, env, ctx) {
      const c = env.HYPERDRIVE.connectionString;
      const v = env["MY_KV"];
      const { SECRET } = env;
      return new Response(c);
    } };`;
    const source = parse("index.ts", text);
    const map = buildBindingMap(source);
    expect(map.used.has("HYPERDRIVE")).toBe(true);
    expect(map.used.has("MY_KV")).toBe(true);
    expect(map.used.has("SECRET")).toBe(true);
    expect(map.envDestructured).toBe(true);
    const hd = map.refs.find((r) => r.name === "HYPERDRIVE");
    expect(hd?.accessType).toBe("dot");
  });
});

describe("predicate helpers", () => {
  it("looksLikeSecret matches vendor key shapes, not plain strings", () => {
    const lit = (v: string) =>
      findNodes(parse("t.ts", `const x = ${JSON.stringify(v)};`).ast, "Literal")[0]!.node;
    expect(looksLikeSecret(lit("sk_live_abcdef0123456789ghij"))).toBe(true);
    expect(looksLikeSecret(lit("hello world"))).toBe(false);
  });

  it("isSuccessValue detects allow-shaped verdicts", () => {
    const obj = findNodes(
      parse("t.ts", `const x = ({ decision: "allow" });`).ast,
      "ObjectExpression",
    )[0]!.node;
    expect(isSuccessValue(obj)).toBe(true);
  });
});

describe("audit command", () => {
  it("flags the vulnerable fixture and exits 1 under --strict", () => {
    const { output, exitCode } = runAudit([vulnerable], { source: true, strict: true });
    expect(exitCode).toBe(1);
    for (const id of [
      "WF-BIND-01",
      "WF-EGR-01",
      "WF-WFP-01",
      "WF-CFG-01",
      "WF-FAIL-01",
      "WF-INJ-01",
      "WF-INJ-02",
      "WF-SEC-01",
    ]) {
      expect(output).toContain(id);
    }
  });

  it("emits valid JSON with a counts block", () => {
    const { output } = runAudit([vulnerable], { source: true, json: true });
    const parsed = JSON.parse(output);
    expect(parsed.sources).toHaveLength(2);
    expect(parsed.counts.high).toBeGreaterThan(0);
  });

  it("produces no high/critical findings on the clean fixture", () => {
    const { exitCode } = runAudit([clean], { source: true, strict: true });
    expect(exitCode).toBe(0);
  });

  it("suppresses findings listed in --ignore", () => {
    const { output } = runAudit([vulnerable], { source: true, ignore: "WF-BIND-01,WF-INJ-01" });
    expect(output).not.toContain("WF-BIND-01");
    expect(output).not.toContain("WF-INJ-01");
    expect(output).toContain("WF-BIND-04");
  });
});

describe("phase 2 predicate helpers", () => {
  it("isTimingUnsafeComparison flags secret-named equality, not arbitrary ===", () => {
    expect(isTimingUnsafeComparison(firstOfType("if (apiToken === x) {}", "BinaryExpression"))).toBe(true);
    expect(isTimingUnsafeComparison(firstOfType("if (count === 3) {}", "BinaryExpression"))).toBe(false);
  });

  it("referencesRequestInput detects request-derived expressions", () => {
    expect(referencesRequestInput(firstOfType("f(request.url)", "CallExpression"))).toBe(true);
    expect(referencesRequestInput(firstOfType("f(staticValue)", "CallExpression"))).toBe(false);
  });

  it("calleeMemberPath resolves dotted callees", () => {
    expect(calleeMemberPath(firstOfType("puppeteer.launch(x)", "CallExpression"))).toEqual([
      "puppeteer",
      "launch",
    ]);
    expect(calleeMemberPath(firstOfType("this.sql.exec(q)", "CallExpression"))).toEqual(["sql", "exec"]);
  });

  it("isMutableContainer / template / concat predicates", () => {
    expect(isMutableContainer(firstOfType("const m = new Map();", "NewExpression"))).toBe(true);
    expect(isMutableContainer(firstOfType("const a = [];", "ArrayExpression"))).toBe(true);
    expect(templateHasExpressions(firstOfType("const q = `a ${b}`;", "TemplateLiteral"))).toBe(true);
    expect(isStringConcat(firstOfType("const s = 'a' + b;", "BinaryExpression"))).toBe(true);
  });

  it("secretBindingNames classifies credential + secret-named bindings", () => {
    const { config } = parseWrangler(join(families, "wrangler.toml"));
    const names = secretBindingNames(config);
    expect(names.has("API_SECRET")).toBe(true); // Secrets Store
    expect(names.has("HYPERDRIVE")).toBe(true); // credential category
  });
});

describe("phase 2 source rules — full family coverage", () => {
  const EXPECTED_SOURCE_RULES = [
    "WF-SEC-01", "WF-SEC-02", "WF-SEC-03",
    "WF-INJ-01", "WF-INJ-02", "WF-INJ-03", "WF-INJ-04",
    "WF-STATE-01", "WF-STATE-02",
    "WF-CRYPTO-01", "WF-CRYPTO-02",
    "WF-FAIL-01", "WF-FAIL-02", "WF-FAIL-03",
    "WF-RES-01", "WF-RES-02",
    "WF-BUSE-01", "WF-BUSE-02", "WF-BUSE-03", "WF-BUSE-04",
  ];

  it("fires every family A–G source rule on the families fixture", () => {
    const { output } = runAudit([families], { source: true, json: true });
    const parsed = JSON.parse(output);
    const src = parsed.sources.find((s: { source: string }) => s.source.endsWith("index.ts"));
    const ids: string[] = src.findings.map((f: { rule_id: string }) => f.rule_id);
    for (const id of EXPECTED_SOURCE_RULES) {
      expect(ids, `expected ${id} to fire`).toContain(id);
    }
  });

  it("emits no duplicate (rule_id, resource) findings", () => {
    const { output } = runAudit([families], { source: true, json: true });
    const parsed = JSON.parse(output);
    const src = parsed.sources.find((s: { source: string }) => s.source.endsWith("index.ts"));
    const keys = src.findings.map((f: { rule_id: string; resource: string }) => `${f.rule_id}::${f.resource}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("does not flag the clean fixture's source", () => {
    const { output } = runAudit([clean], { source: true, json: true });
    const parsed = JSON.parse(output);
    const src = parsed.sources.find((s: { source: string }) => s.source.endsWith("index.ts"));
    expect(src.findings).toHaveLength(0);
  });
});

describe("expanded Worker source and supply-chain rules", () => {
  const NEW_RULE_IDS = [
    "WF-REQ-SSRF-01",
    "WF-REQ-REDIR-01",
    "WF-REQ-CORS-01",
    "WF-REQ-HDR-01",
    "WF-CACHE-POISON-01",
    "WF-CACHE-POISON-02",
    "WF-CACHE-SENSITIVE-01",
    "WF-HANDLER-PRIV-01",
    "WF-SVC-AUTH-01",
    "WF-SVC-AUTH-02",
    "WF-SC-PKG-01",
    "WF-SC-PKG-02",
    "WF-SC-DOCKER-01",
    "WF-SC-DOCKER-02",
    "WF-SC-PY-01",
  ];

  it("scans helper source files beyond wrangler main", () => {
    const { output } = runAudit([rulesBad], { source: true, json: true });
    const sources = parsedSources(output);
    expect(sources.some((s) => s.source.endsWith("src/helper.ts"))).toBe(true);
    const helper = sources.find((s) => s.source.endsWith("src/helper.ts"));
    expect(helper?.findings.map((f) => f.rule_id)).toContain("WF-REQ-SSRF-01");
  });

  it("fires the new request, cache, handler, service, and supply-chain rules", () => {
    const { output } = runAudit([rulesBad], { source: true, json: true, severity: "informational" });
    const ids = allRuleIds(output);
    for (const id of NEW_RULE_IDS) {
      expect(ids, `expected ${id} to fire`).toContain(id);
    }
  });

  it("does not flag safe static fetch, allowlisted redirect, cache key, guarded queue, or service auth propagation", () => {
    const { output } = runAudit([rulesSafe], { source: true, json: true, severity: "informational" });
    const ids = allRuleIds(output);
    for (const id of [
      "WF-REQ-SSRF-01",
      "WF-REQ-REDIR-01",
      "WF-CACHE-POISON-01",
      "WF-CACHE-POISON-02",
      "WF-HANDLER-PRIV-01",
      "WF-SVC-AUTH-01",
    ]) {
      expect(ids).not.toContain(id);
    }
  });

  it("raises wildcard CORS severity when sensitive bindings are declared", () => {
    const { output } = runAudit([rulesBad], { source: true, json: true, severity: "informational" });
    const corsFindings = allFindings(output).filter((f) => f.rule_id === "WF-REQ-CORS-01");
    expect(corsFindings.length).toBeGreaterThan(0);
    expect(corsFindings.some((f) => f.severity === "high")).toBe(true);
  });

  it("reports wildcard CORS without sensitive bindings at low severity", () => {
    const { output } = runAudit([corsLow], { source: true, json: true, severity: "informational" });
    const corsFindings = allFindings(output).filter((f) => f.rule_id === "WF-REQ-CORS-01");
    expect(corsFindings).toHaveLength(1);
    expect(corsFindings[0]?.severity).toBe("low");
  });

  it("flags a package-manager project without a lockfile", () => {
    const dir = mkdtempSync(join(tmpdir(), "wulf-lock-"));
    try {
      mkdirSync(join(dir, "src"));
      writeFileSync(join(dir, "wrangler.toml"), 'name = "no-lock"\nmain = "src/index.ts"\ncompatibility_date = "2026-05-01"\n');
      writeFileSync(join(dir, "package.json"), '{"name":"no-lock","dependencies":{"left-pad":"1.3.0"}}\n');
      writeFileSync(join(dir, "src", "index.ts"), 'export default { fetch() { return new Response("ok"); } };\n');
      const { output } = runAudit([dir], { source: true, json: true, severity: "informational" });
      expect(allRuleIds(output)).toContain("WF-SC-LOCK-01");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
