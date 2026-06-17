#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);
const defaultTargets = ["test-fixtures/wulf-config"];

function walk(dir) {
  if (!existsSync(dir)) return [];
  const entries = readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) return walk(path);
    return /(?:wrangler\.(?:toml|jsonc?)|\.toml|\.jsonc?)$/.test(entry.name) ? [path] : [];
  });
}

function parseAnnotations(file) {
  const rel = relative(repoRoot, file);
  const text = readFileSync(file, "utf8");
  const expected = [];
  const forbidden = [];

  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const ruleId = line.match(/#\s*ruleid:\s*([A-Za-z0-9_.-]+)/) ?? line.match(/\/\/\s*ruleid:\s*([A-Za-z0-9_.-]+)/);
    if (ruleId) expected.push({ file: rel, line: index + 1, rule: ruleId[1] });

    const ok = line.match(/#\s*ok:\s*([A-Za-z0-9_.-]+)/) ?? line.match(/\/\/\s*ok:\s*([A-Za-z0-9_.-]+)/);
    if (ok) forbidden.push({ file: rel, line: index + 1, rule: ok[1] });
  }

  return { expected, forbidden };
}

function lineNumber(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}

function dispatchBlocks(text) {
  const starts = [...text.matchAll(/^\s*\[\[dispatch_namespaces\]\]\s*$/gim)].map((match) => match.index ?? 0);
  return starts.map((start, i) => {
    const end = starts[i + 1] ?? text.length;
    return { start, text: text.slice(start, end) };
  });
}

function lintToml(file) {
  const rel = relative(repoRoot, file);
  const text = readFileSync(file, "utf8");
  const findings = [];

  for (const block of dispatchBlocks(text)) {
    const trusted = block.text.match(/^\s*trusted_workers\s*=\s*true\s*$/im);
    if (trusted) {
      findings.push({ file: rel, line: lineNumber(text, block.start + (trusted.index ?? 0)), rule: "wulf-wfp-trusted-namespace" });
    }

    if (!/^\s*outbound\s*=/im.test(block.text)) {
      findings.push({ file: rel, line: lineNumber(text, block.start), rule: "wulf-wfp-no-outbound" });
    }
  }

  const deletedClasses = text.match(/^\s*deleted_classes\s*=/im);
  if (deletedClasses) {
    findings.push({ file: rel, line: lineNumber(text, deletedClasses.index ?? 0), rule: "wulf-destructive-do-migration" });
  }

  return findings;
}

const targets = process.argv.slice(2).length > 0 ? process.argv.slice(2) : defaultTargets;
const files = targets.flatMap((target) => walk(resolve(repoRoot, target)));
const annotations = files.flatMap((file) => {
  const parsed = parseAnnotations(file);
  return [...parsed.expected, ...parsed.forbidden];
});

if (annotations.length === 0) {
  console.error(`No config-lint annotations found under ${targets.join(", ")}`);
  process.exit(1);
}

const findings = new Set(files.flatMap(lintToml).map((finding) => `${finding.file}:${finding.rule}`));
const failures = [];

for (const expected of files.flatMap((file) => parseAnnotations(file).expected)) {
  if (!findings.has(`${expected.file}:${expected.rule}`)) {
    failures.push(`missing ${expected.rule} for ${expected.file}:${expected.line}`);
  }
}

for (const forbidden of files.flatMap((file) => parseAnnotations(file).forbidden)) {
  if (findings.has(`${forbidden.file}:${forbidden.rule}`)) {
    failures.push(`unexpected ${forbidden.rule} for ${forbidden.file}:${forbidden.line}`);
  }
}

if (failures.length > 0) {
  console.error("Wulf config-lint fixture check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Wulf config-lint fixture check passed: ${annotations.length} annotations, ${findings.size} findings.`);
