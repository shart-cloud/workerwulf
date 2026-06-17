#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);
const targets = [
  "test-fixtures/wulf-rules",
  "packages/durable/src/durable",
  "packages/worker/src/probes",
];

function shortRule(checkId) {
  return String(checkId).split(".").at(-1);
}

const scan = spawnSync(
  "opengrep",
  [
    "scan",
    "--config",
    "rules/wulf-rules.yml",
    ...targets,
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

const counts = new Map();
for (const result of output.results ?? []) {
  const rule = shortRule(result.check_id);
  counts.set(rule, (counts.get(rule) ?? 0) + 1);
}

console.log(`Wulf corpus scan completed: ${(output.results ?? []).length} findings, 0 errors.`);
for (const [rule, count] of [...counts.entries()].sort()) {
  console.log(`- ${rule}: ${count}`);
}
