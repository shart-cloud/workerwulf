#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);
const canonical = resolve(repoRoot, "rules/wulf-rules.yml");
const targets = [
  resolve(repoRoot, "packages/llamafirewall/container/wulf-rules.yml"),
  resolve(repoRoot, "packages/codeshield/container/wulf-rules.yml"),
];

const checkOnly = process.argv.includes("--check");
const canonicalText = readFileSync(canonical, "utf8");
const drifted = [];

for (const target of targets) {
  const targetText = readFileSync(target, "utf8");
  if (targetText === canonicalText) continue;

  drifted.push(relative(repoRoot, target));
  if (!checkOnly) writeFileSync(target, canonicalText);
}

if (checkOnly && drifted.length > 0) {
  console.error("Wulf rule copies are out of sync with rules/wulf-rules.yml:");
  for (const path of drifted) console.error(`- ${path}`);
  console.error("Run `pnpm rules:sync` to update generated copies.");
  process.exit(1);
}

if (drifted.length > 0) {
  console.log(`Synced ${drifted.length} Wulf rule file(s):`);
  for (const path of drifted) console.log(`- ${path}`);
} else {
  console.log("Wulf rule copies are already in sync.");
}
