import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";

import { buildBindingMap } from "../ast/binding-map.js";
import { parse, type SourceFile } from "../ast/parse.js";
import { mapApiBinding, RestCfClient, type CfClient } from "../cf/client.js";
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

  let client = clientOverride;
  if (!client) {
    if (!accountId || !token) {
      return {
        output:
          "error: missing credentials. Provide --account-id and --api-token, or set " +
          "CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN.",
        exitCode: 2,
      };
    }
    client = new RestCfClient({ accountId, token });
  }

  const minSeverity: Severity = options.severity ?? "low";
  const ignore = new Set(
    (options.ignore ?? "").split(",").map((s) => s.trim()).filter(Boolean),
  );

  let ctx: AccountContext;
  try {
    ctx = await gatherAccountContext(client, accountId ?? "(injected)", options);
  } catch (err) {
    return { output: `error: ${(err as Error).message}`, exitCode: 2 };
  }

  const outcome = runAccountRules(ctx);
  const kept = outcome.findings.filter((f) => !ignore.has(f.rule_id));
  const groups = groupByResource(kept);
  const filtered = groups.map((g) => ({ ...g, findings: atOrAbove(g.findings, minSeverity) }));

  const report = buildReport(randomUUID(), new Date().toISOString(), filtered);
  const all = totalFindings(report);

  const notes: string[] = outcome.errors.map(
    (e) => `note: rule ${e.rule_id} errored: ${e.message}`,
  );
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

async function gatherAccountContext(
  client: CfClient,
  accountId: string,
  options: ScanOptions,
): Promise<AccountContext> {
  const scriptNames = await client.listScripts();
  const scripts: ScriptMetadata[] = [];
  for (const name of scriptNames) {
    const [rawBindings, routes, content] = await Promise.all([
      client.getScriptBindings(name),
      client.getRoutes(name),
      client.getScriptContent(name),
    ]);
    const declared = rawBindings
      .map(mapApiBinding)
      .filter((b): b is NonNullable<typeof b> => b !== undefined);
    let bindingMap: ScriptMetadata["bindingMap"];
    if (content !== undefined) {
      bindingMap = buildBindingMap(parse(`script:${name}`, content));
    }
    scripts.push({
      name,
      declared,
      routes: routes.map((pattern) => ({ pattern })),
      content,
      bindingMap,
    });
  }

  const namespaceNames = options.namespace
    ? [options.namespace]
    : await client.listNamespaces();
  const namespaces: WfPNamespace[] = [];
  for (const name of namespaceNames) {
    const raw = await client.getNamespace(name);
    if (!raw) continue;
    namespaces.push({
      name: raw.name,
      trusted: Boolean(raw.trusted),
      hasOutbound: Boolean(raw.outbound),
      hasLimits: Boolean(raw.limits),
      scripts: (raw.scripts ?? []).map((s) => ({
        name: s.name,
        untrusted: s.untrusted === true,
      })),
    });
  }

  const localSources = options.source ? loadLocalSources(options.source) : undefined;
  return { accountId, scripts, namespaces, localSources };
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
