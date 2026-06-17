#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);
const rulesPath = "rules/wulf-rules.yml";
const fixturesPath = "test-fixtures/wulf-rules";
const requiredWulfMetadata = [
  "wulf_smell",
  "family",
  "surfaces",
  "trust_context",
  "validated_by",
  "severity_base",
  "substrate",
  "precision_risk",
  "source",
];

function walk(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) return walk(path);
    return /(?:\.[cm]?[jt]sx?|\.toml)$/.test(entry.name) ? [path] : [];
  });
}

function parseAnnotations(file) {
  const rel = relative(repoRoot, file);
  const text = readFileSync(file, "utf8");
  const expected = [];
  const forbidden = [];

  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const ruleId = line.match(/\/\/\s*ruleid:\s*([A-Za-z0-9_.-]+)/);
    if (ruleId) expected.push({ file: rel, line: index + 1, rule: ruleId[1] });

    const hashRuleId = line.match(/#\s*ruleid:\s*([A-Za-z0-9_.-]+)/);
    if (hashRuleId) expected.push({ file: rel, line: index + 1, rule: hashRuleId[1] });

    const ok = line.match(/\/\/\s*ok:\s*([A-Za-z0-9_.-]+)/);
    if (ok) forbidden.push({ file: rel, line: index + 1, rule: ok[1] });

    const hashOk = line.match(/#\s*ok:\s*([A-Za-z0-9_.-]+)/);
    if (hashOk) forbidden.push({ file: rel, line: index + 1, rule: hashOk[1] });
  }

  return { expected, forbidden };
}

function shortRule(checkId) {
  return String(checkId).split(".").at(-1);
}

function validateWulfMetadata() {
  const text = readFileSync(resolve(repoRoot, rulesPath), "utf8");
  const failures = [];
  const ruleBlocks = text.split(/\n(?=  - id: )/g).filter((block) => block.includes("  - id: "));

  for (const block of ruleBlocks) {
    const id = block.match(/  - id:\s*([^\n]+)/)?.[1]?.trim() ?? "unknown";
    if (!block.includes("wulf_smell:")) continue;

    for (const field of requiredWulfMetadata) {
      if (!new RegExp(`\\n\\s+${field}:`).test(block)) {
        failures.push(`${id} missing metadata.${field}`);
      }
    }
  }

  return failures;
}

const fixtureFiles = walk(resolve(repoRoot, fixturesPath));
const annotations = fixtureFiles.flatMap((file) => {
  const parsed = parseAnnotations(file);
  return [...parsed.expected, ...parsed.forbidden];
});

if (annotations.length === 0) {
  console.error(`No rule annotations found under ${fixturesPath}`);
  process.exit(1);
}

const scan = spawnSync(
  "opengrep",
  [
    "scan",
    "--config",
    rulesPath,
    fixturesPath,
    "--json",
    "--quiet",
    "--no-git-ignore",
  ],
  { cwd: repoRoot, encoding: "utf8" },
);

if (scan.error) {
  console.error(`Failed to run opengrep: ${scan.error.message}`);
  process.exit(1);
}

if (![0, 2].includes(scan.status)) {
  process.stderr.write(scan.stderr);
  process.stderr.write(scan.stdout);
  process.exit(scan.status ?? 1);
}

let output;
try {
  output = JSON.parse(scan.stdout);
} catch (err) {
  console.error(`Failed to parse opengrep JSON: ${err instanceof Error ? err.message : String(err)}`);
  process.stderr.write(scan.stderr);
  process.stderr.write(scan.stdout);
  process.exit(1);
}

if (output.errors?.length) {
  console.error("OpenGrep reported rule/config errors:");
  for (const err of output.errors) {
    console.error(`- ${err.rule_id ?? err.type ?? "unknown"}: ${err.message ?? err.long_msg ?? JSON.stringify(err)}`);
  }
  process.exit(1);
}

const findings = new Set(
  (output.results ?? []).map((result) => `${result.path}:${shortRule(result.check_id)}`),
);

const allExpected = fixtureFiles.flatMap((file) => parseAnnotations(file).expected);
const allForbidden = fixtureFiles.flatMap((file) => parseAnnotations(file).forbidden);
const failures = validateWulfMetadata();

for (const expected of allExpected) {
  if (!findings.has(`${expected.file}:${expected.rule}`)) {
    failures.push(`missing ${expected.rule} for ${expected.file}:${expected.line}`);
  }
}

for (const forbidden of allForbidden) {
  if (findings.has(`${forbidden.file}:${forbidden.rule}`)) {
    failures.push(`unexpected ${forbidden.rule} for ${forbidden.file}:${forbidden.line}`);
  }
}

if (failures.length > 0) {
  console.error("Wulf rule fixture check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `Wulf rule fixture check passed: ${allExpected.length} expected positives, ${allForbidden.length} expected negatives, ${(output.results ?? []).length} findings.`,
);
