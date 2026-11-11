import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { randomUUID } from "node:crypto";

import { auditProject, hasHighOrAbove, type Severity } from "@wulf/analyze";

import {
  buildReport,
  renderHuman,
  renderJson,
  totalFindings,
  type FindingGroup,
} from "../engine/output.js";
import { diskFiles } from "../files.js";
import { parseWrangler } from "../parsers/wrangler.js";
import { saveRunReport } from "../report/persist.js";

const CONFIG_NAMES = ["wrangler.toml", "wrangler.json", "wrangler.jsonc"];
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".wrangler",
  ".netlify",
  ".vercel",
  ".output",
  ".svelte-kit",
  "coverage",
  "results",
  "netlify-target",
  "test",
  "tests",
  "__tests__",
  ".turbo",
  ".next",
  "out",
]);
const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

export interface AuditOptions {
  source?: boolean;
  strict?: boolean;
  json?: boolean;
  severity?: Severity;
  ignore?: string;
  /** Persist the run report JSON to this directory for `wulf report`. */
  save?: string;
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

    const sources: { path: string; text: () => string }[] = [];
    if (options.source) {
      if (parsed.config.main) {
        const mainPath = resolve(dirname(configPath), parsed.config.main);
        if (!existsSync(mainPath)) notes.push(`Source entry not found for ${rel}: ${parsed.config.main}`);
      }
      for (const sourcePath of discoverSourceFiles(dirname(configPath), parsed.config.main)) {
        sources.push({
          path: relative(cwd, sourcePath) || sourcePath,
          text: () => readFileSync(sourcePath, "utf8"),
        });
      }
    }

    const project = auditProject({
      configPath: rel,
      config: parsed.config,
      sources,
      files: diskFiles(configPath),
      ignore,
      severity: minSeverity,
    });
    groups.push(...project.groups);
    notes.push(...project.notes);
  }

  const report = buildReport(randomUUID(), new Date().toISOString(), groups);
  const all = totalFindings(report);

  if (options.save) {
    const saved = saveRunReport(report, options.save);
    notes.push(`saved run report to ${saved}`);
  }

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

function discoverSourceFiles(root: string, main: string | undefined): string[] {
  const found = new Set<string>();
  if (main) {
    const sourcePath = resolve(root, main);
    if (existsSync(sourcePath) && statSync(sourcePath).isFile() && isSourceFile(sourcePath)) {
      found.add(sourcePath);
    }
  }
  walkSourceDir(root, found);
  return [...found].sort((a, b) => {
    if (main) {
      const mainPath = resolve(root, main);
      if (a === mainPath) return -1;
      if (b === mainPath) return 1;
    }
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function walkSourceDir(dir: string, found: Set<string>): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walkSourceDir(path, found);
    } else if (entry.isFile() && isSourceFile(path)) {
      found.add(path);
    }
  }
}

function isSourceFile(path: string): boolean {
  if (path.endsWith(".d.ts")) return false;
  return SOURCE_EXTS.has(extname(path));
}
