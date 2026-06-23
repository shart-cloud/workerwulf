import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { randomUUID } from "node:crypto";

import { buildBindingMap } from "../ast/binding-map.js";
import { parse } from "../ast/parse.js";
import {
  buildReport,
  renderHuman,
  renderJson,
  totalFindings,
  type FindingGroup,
} from "../engine/output.js";
import type { Finding, Severity } from "../engine/rule.js";
import {
  atOrAbove,
  hasHighOrAbove,
  runConfigRules,
  runSourceRules,
} from "../engine/runner.js";
import { parseWrangler, resolveEnvironments } from "../parsers/wrangler.js";
import "../rules/index.js";

const CONFIG_NAMES = ["wrangler.toml", "wrangler.json", "wrangler.jsonc"];
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".wrangler"]);

export interface AuditOptions {
  source?: boolean;
  strict?: boolean;
  json?: boolean;
  severity?: Severity;
  ignore?: string;
}

export interface AuditRunResult {
  output: string;
  exitCode: number;
}

/** Find every wrangler config reachable from the given paths. */
function discoverConfigs(paths: string[]): string[] {
  const found = new Set<string>();
  for (const p of paths) {
    const abs = resolve(p);
    if (!existsSync(abs)) continue;
    const st = statSync(abs);
    if (st.isFile()) {
      if (CONFIG_NAMES.some((n) => abs.endsWith(n))) found.add(abs);
      continue;
    }
    if (st.isDirectory()) walkDir(abs, found);
  }
  return [...found].sort();
}

function walkDir(dir: string, found: Set<string>): void {
  for (const name of CONFIG_NAMES) {
    const candidate = join(dir, name);
    if (existsSync(candidate)) found.add(candidate);
  }
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (SKIP_DIRS.has(entry.name)) continue;
    walkDir(join(dir, entry.name), found);
  }
}

export function runAudit(paths: string[], options: AuditOptions): AuditRunResult {
  const cwd = process.cwd();
  const minSeverity: Severity = options.severity ?? "low";
  const ignore = new Set(
    (options.ignore ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );

  const configs = discoverConfigs(paths.length > 0 ? paths : ["."]);
  const groups: FindingGroup[] = [];
  const notes: string[] = [];

  if (configs.length === 0) {
    notes.push("No wrangler.toml / wrangler.json found in the given path(s).");
  }

  for (const configPath of configs) {
    const rel = relative(cwd, configPath) || configPath;
    let parsed;
    try {
      parsed = parseWrangler(configPath);
    } catch (err) {
      notes.push(`Failed to parse ${rel}: ${(err as Error).message}`);
      continue;
    }

    // Config rules across every resolved environment, deduped by (rule, resource).
    const configFindings: Finding[] = [];
    const seen = new Set<string>();
    for (const env of resolveEnvironments(parsed.config)) {
      const outcome = runConfigRules({
        config: env.config,
        configPath: rel,
        envName: env.name,
      });
      for (const f of outcome.findings) {
        const key = `${f.rule_id}::${f.resource}`;
        if (env.name === "default") {
          seen.add(key);
          configFindings.push(f);
        } else if (!seen.has(key)) {
          seen.add(key);
          configFindings.push({ ...f, resource: `${f.resource} [env:${env.name}]` });
        }
      }
    }
    groups.push({ kind: "config", source: rel, findings: applyIgnore(configFindings, ignore) });

    // Source rules — base config's `main` entry point, if --source.
    if (options.source && parsed.config.main) {
      const sourcePath = resolve(dirname(configPath), parsed.config.main);
      const sourceRel = relative(cwd, sourcePath) || sourcePath;
      if (!existsSync(sourcePath)) {
        notes.push(`Source entry not found for ${rel}: ${parsed.config.main}`);
      } else {
        const text = readFileSync(sourcePath, "utf8");
        const source = parse(sourceRel, text);
        if (source.errors.length > 0) {
          notes.push(`Parse warnings in ${sourceRel}: ${source.errors.length} (continuing)`);
        }
        const bindingMap = buildBindingMap(source);
        const outcome = runSourceRules({
          config: parsed.config,
          configPath: rel,
          source,
          bindingMap,
        });
        groups.push({
          kind: "source",
          source: sourceRel,
          findings: applyIgnore(outcome.findings, ignore),
        });
      }
    }
  }

  // Apply the severity threshold to every group.
  const filteredGroups = groups.map((g) => ({
    ...g,
    findings: atOrAbove(g.findings, minSeverity),
  }));

  const report = buildReport(randomUUID(), new Date().toISOString(), filteredGroups);
  const all = totalFindings(report);

  let output: string;
  if (options.json) {
    output = renderJson(report);
  } else {
    const parts = [renderHuman(report)];
    if (notes.length > 0) {
      parts.push("", ...notes.map((n) => `note: ${n}`));
    }
    output = parts.join("\n");
  }

  const exitCode = options.strict && hasHighOrAbove(all) ? 1 : 0;
  return { output, exitCode };
}

function applyIgnore(findings: Finding[], ignore: Set<string>): Finding[] {
  if (ignore.size === 0) return findings;
  return findings.filter((f) => !ignore.has(f.rule_id));
}
