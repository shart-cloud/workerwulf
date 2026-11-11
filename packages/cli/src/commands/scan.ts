import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";

import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import {
  cfApiFromPromises,
  cfApiRest,
  collectAccount,
  type AccountSnapshot,
  type CfApi,
  type Coverage,
} from "@wulf/core";
import type * as Layer from "effect/Layer";

import { buildBindingMap } from "../ast/binding-map.js";
import { parse, type SourceFile } from "../ast/parse.js";
import { mapApiBinding, type CfClient } from "../cf/client.js";
import {
  buildReport,
  renderHuman,
  renderJson,
  totalFindings,
  type FindingGroup,
} from "../engine/output.js";
import type {
  AccountContext,
  Finding,
  ScriptMetadata,
  WfPNamespace,
} from "../engine/rule.js";
import { atOrAbove, hasHighOrAbove, runAccountRules } from "../engine/runner.js";
import type { Severity } from "../engine/rule.js";
import { parseWrangler } from "../parsers/wrangler.js";
import { saveRunReport } from "../report/persist.js";
import "../rules/index.js";

const CONFIG_NAMES = ["wrangler.toml", "wrangler.json", "wrangler.jsonc"];
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".wrangler"]);

export interface ScanOptions {
  accountId?: string;
  apiToken?: string;
  source?: string;
  namespace?: string;
  json?: boolean;
  strict?: boolean;
  severity?: Severity;
  ignore?: string;
  /** Persist the run report JSON to this directory for `wulf report`. */
  save?: string;
}

export interface ScanRunResult {
  output: string;
  exitCode: number;
}

/**
 * Run a live account scan. `clientOverride` lets tests (and alternate API
 * backends) inject a CfClient; in normal use a RestCfClient is built from
 * --account-id/--api-token (or CLOUDFLARE_ACCOUNT_ID/CLOUDFLARE_API_TOKEN).
 */
export async function runScan(
  options: ScanOptions,
  clientOverride?: CfClient,
): Promise<ScanRunResult> {
  const accountId = options.accountId ?? process.env["CLOUDFLARE_ACCOUNT_ID"];
  const token = options.apiToken ?? process.env["CLOUDFLARE_API_TOKEN"];

  let api: Layer.Layer<CfApi>;
  if (clientOverride) {
    api = cfApiFromPromises(accountId ?? "(injected)", clientOverride);
  } else {
    if (!accountId || !token) {
      return {
        output:
          "error: missing credentials. Provide --account-id and --api-token, or set " +
          "CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN.",
        exitCode: 2,
      };
    }
    api = cfApiRest({ accountId, token: Redacted.make(token) });
  }

  const minSeverity: Severity = options.severity ?? "low";
  const ignore = new Set(
    (options.ignore ?? "").split(",").map((s) => s.trim()).filter(Boolean),
  );

  const collected = await Effect.runPromise(
    collectAccount(options.namespace !== undefined ? { namespace: options.namespace } : {}).pipe(
      Effect.provide(api),
      Effect.result,
    ),
  );
  if (collected._tag === "Failure") {
    const e = collected.failure;
    const why = e._tag === "PermissionDenied" ? `permission denied (HTTP ${e.status})` : e._tag;
    return { output: `error: cannot list Workers scripts: ${why} on ${e.path}`, exitCode: 2 };
  }
  const snapshot = collected.success;
  const ctx = toAccountContext(snapshot, options);
  const gaps = snapshot.coverage.filter((c) => c.status !== "complete");

  const outcome = runAccountRules(ctx);
  const kept = outcome.findings.filter((f) => !ignore.has(f.rule_id));
  const groups = groupByResource(kept);
  const filtered = groups.map((g) => ({ ...g, findings: atOrAbove(g.findings, minSeverity) }));

  const report = buildReport(randomUUID(), new Date().toISOString(), filtered, gaps);
  const all = totalFindings(report);

  const notes: string[] = [
    ...gaps.map(coverageNote),
    ...outcome.errors.map((e) => `note: rule ${e.rule_id} errored: ${e.message}`),
  ];
  if (options.save) {
    notes.push(`note: saved run report to ${saveRunReport(report, options.save)}`);
  }

  let output: string;
  if (options.json) {
    output = renderJson(report);
  } else {
    const parts = [renderHuman(report)];
    if (notes.length > 0) parts.push("", ...notes);
    output = parts.join("\n");
  }

  const exitCode = options.strict && hasHighOrAbove(all) ? 1 : 0;
  return { output, exitCode };
}

/**
 * Shape a collected snapshot into the rules' AccountContext. A read that didn't
 * complete becomes an empty value here (the rules expect arrays), and the
 * matching coverage note tells the user those rules ran on partial data.
 */
function toAccountContext(snapshot: AccountSnapshot, options: ScanOptions): AccountContext {
  const scripts: ScriptMetadata[] = snapshot.scripts.map((s) => {
    const declared = (s.bindings ?? [])
      .map(mapApiBinding)
      .filter((b): b is NonNullable<typeof b> => b !== undefined);
    return {
      name: s.name,
      declared,
      routes: (s.routes ?? []).map((pattern) => ({ pattern })),
      content: s.content,
      bindingMap:
        s.content !== undefined ? buildBindingMap(parse(`script:${s.name}`, s.content)) : undefined,
    };
  });

  const namespaces: WfPNamespace[] = snapshot.namespaces.map((raw) => ({
    name: raw.name,
    trusted: Boolean(raw.trusted),
    hasOutbound: Boolean(raw.outbound),
    hasLimits: Boolean(raw.limits),
    scripts: (raw.scripts ?? []).map((s) => ({ name: s.name, untrusted: s.untrusted === true })),
  }));

  const localSources = options.source ? loadLocalSources(options.source) : undefined;
  return { accountId: snapshot.accountId, scripts, namespaces, localSources };
}

const AFFECTED_RULES: Record<string, string> = {
  bindings: "binding and least-privilege rules",
  routes: "public-route rules",
  content: "binding-use and drift rules",
  listNamespaces: "WfP namespace rules",
  namespace: "WfP namespace rules",
};

function coverageNote(c: Coverage): string {
  const affected = AFFECTED_RULES[c.op] ?? "related rules";
  const detail = c.detail ? ` (${c.detail})` : "";
  return `note: ${c.target} ${c.op}: ${c.status}${detail}; ${affected} ran on partial data`;
}

/** Map deployed-script name → local SourceFile, keyed by wrangler `name`. */
function loadLocalSources(sourceDir: string): Map<string, SourceFile> {
  const map = new Map<string, SourceFile>();
  for (const configPath of discoverConfigs(sourceDir)) {
    try {
      const { config } = parseWrangler(configPath);
      if (!config.name || !config.main) continue;
      const mainPath = resolve(dirname(configPath), config.main);
      if (!existsSync(mainPath)) continue;
      map.set(config.name, parse(config.main, readFileSync(mainPath, "utf8")));
    } catch {
      // Skip unparseable configs — drift simply won't run for them.
    }
  }
  return map;
}

function discoverConfigs(dir: string): string[] {
  const abs = resolve(dir);
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const name of CONFIG_NAMES) {
      const candidate = join(d, name);
      if (existsSync(candidate)) out.push(candidate);
    }
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) walk(join(d, entry.name));
    }
  };
  if (existsSync(abs) && statSync(abs).isDirectory()) walk(abs);
  return out;
}

/** Bucket findings into FindingGroups by their resource prefix (script:/namespace:). */
function groupByResource(findings: Finding[]): FindingGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const m = f.resource.match(/^(script:[^:]+|namespace:[^:]+)/);
    const key = m ? m[1]! : "account";
    const list = groups.get(key);
    if (list) list.push(f);
    else groups.set(key, [f]);
  }
  return [...groups.entries()].map(([source, fs]) => ({
    kind: "account" as const,
    source,
    findings: fs,
  }));
}
