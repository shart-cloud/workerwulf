import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { Finding } from "@wulf/cli/src/engine/rule.js";

export const here = dirname(fileURLToPath(import.meta.url));
export const pocDir = resolve(here, "..");
export const cliDir = resolve(pocDir, "../cli");
export const packagesDir = resolve(pocDir, "..");

/** The CLI's own native binding, exactly as `wulf` loads it. */
const cliRequire = createRequire(join(cliDir, "package.json"));
const native = cliRequire("oxc-parser") as {
  parseSync(f: string, s: string, o: object): { program: unknown; errors: unknown[] };
};

export const langOf = (path: string) =>
  path.endsWith(".ts") ? "ts" : path.endsWith(".tsx") ? "tsx" : path.endsWith(".jsx") ? "jsx" : "js";

export const nativeParse = (path: string, text: string) =>
  native.parseSync(path, text, { sourceType: "module", lang: langOf(path) });

/** JSON round-trip: what crosses an RPC/HTTP boundary, and what rules can observe. */
export const normalize = (v: unknown): unknown => JSON.parse(JSON.stringify(v));

/** First differing path between two JSON values, or undefined when equal. */
export function firstDiff(a: unknown, b: unknown, path = "$"): string | undefined {
  if (Object.is(a, b)) return undefined;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") {
    return `${path}: ${JSON.stringify(a)?.slice(0, 80)} !== ${JSON.stringify(b)?.slice(0, 80)}`;
  }
  if (Array.isArray(a) !== Array.isArray(b)) return `${path}: array vs object`;
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  for (const k of new Set([...ka, ...kb])) {
    const d = firstDiff((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], `${path}.${k}`);
    if (d) return d;
  }
  return undefined;
}

const SKIP = new Set(["node_modules", "dist", ".wrangler", "results", "container"]);

/** Every .ts/.js under a directory, skipping build output and dependencies. */
export function sourceFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (!SKIP.has(e.name)) walk(join(d, e.name));
      } else if ([".ts", ".tsx", ".js", ".mjs"].includes(extname(e.name)) && !e.name.endsWith(".d.ts")) {
        out.push(join(d, e.name));
      }
    }
  };
  walk(root);
  return out;
}

export const fixtureDirs = (): string[] => {
  const root = join(cliDir, "test", "fixtures");
  return readdirSync(root)
    .map((n) => join(root, n))
    .filter((d) => statSync(d).isDirectory() && readdirSync(d).includes("wrangler.toml"));
};

export interface Reference {
  sources: Array<{ source: string; findings: Finding[] }>;
}

const references = new Map<string, Reference>();

/** The real CLI (native parser, real filesystem): `wulf audit . --source --json`. Cached per fixture. */
export function referenceAudit(fixtureDir: string): Reference {
  const cached = references.get(fixtureDir);
  if (cached) return cached;
  const tsx = join(cliDir, "node_modules", ".bin", "tsx");
  const out = execFileSync(tsx, [join(cliDir, "src", "index.ts"), "audit", ".", "--source", "--json"], {
    cwd: fixtureDir,
    encoding: "utf8",
  });
  const reference = JSON.parse(out) as Reference;
  references.set(fixtureDir, reference);
  return reference;
}

/** Supply-chain rules read Dockerfile/package.json from disk; a Worker gets text only. */
export const FS_RULE = /^WF-SC-/;
export const withoutFsRules = (sources: Reference["sources"]) =>
  sources.map((s) => ({ source: s.source, findings: s.findings.filter((f) => !FS_RULE.test(f.rule_id)) }));

export function inputFor(fixtureDir: string, reference: Reference) {
  const files = reference.sources
    .map((s) => s.source)
    .filter((s) => s !== "wrangler.toml")
    .map((path) => ({ path, text: readFileSync(join(fixtureDir, path), "utf8") }));
  return {
    configPath: "wrangler.toml",
    configText: readFileSync(join(fixtureDir, "wrangler.toml"), "utf8"),
    files,
  };
}

export const rel = (p: string) => relative(packagesDir, p);

/** `wrangler dev` on a free-ish port; resolves once /health answers. */
export async function startWorkerd(port: number): Promise<{ url: string; stop: () => void }> {
  const proc: ChildProcess = spawn(
    join(pocDir, "node_modules", ".bin", "wrangler"),
    ["dev", "--port", String(port), "--ip", "127.0.0.1", "--show-interactive-dev-session=false"],
    { cwd: pocDir, stdio: "ignore", detached: true },
  );
  const url = `http://127.0.0.1:${port}`;
  const stop = () => {
    try {
      process.kill(-proc.pid!, "SIGTERM");
    } catch {
      /* already gone */
    }
  };
  for (let i = 0; i < 120; i++) {
    try {
      if ((await fetch(`${url}/health`)).ok) return { url, stop };
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  stop();
  throw new Error("wrangler dev did not become ready");
}
