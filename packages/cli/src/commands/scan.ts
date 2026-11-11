import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";

import * as Effect from "effect/Effect";
import type * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import {
  analyzeAccount,
  hasHighOrAbove,
  parse,
  summarizeSnapshot,
  type AccountSummary,
  type SourceFile,
  type Severity,
} from "@wulf/analyze";
import { cfApiFromPromises, cfApiRest, collectAccount, type CfApi, type Coverage } from "@wulf/core";

import type { CfClient } from "../cf/client.js";
import { buildReport, renderHuman, renderJson, totalFindings } from "../engine/output.js";
import { parseWrangler } from "../parsers/wrangler.js";
import { saveRunReport } from "../report/persist.js";

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
  /** Send the scan to this ScanHub (`@wulf/hub`) base URL. Needs WULF_HUB_TOKEN. */
  push?: string;
  /** Bearer token for --push (or WULF_HUB_TOKEN). */
  pushToken?: string;
}

/** The parts of `fetch` that --push uses, so tests can stand in for the hub. */
export type PushFetch = (url: string, init: RequestInit) => Promise<Response>;

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
  pushFetch: PushFetch = (url, init) => fetch(url, init),
): Promise<ScanRunResult> {
  const startedAt = new Date().toISOString();
  const pushToken = options.pushToken ?? process.env["WULF_HUB_TOKEN"];
  if (options.push !== undefined) {
    if (options.namespace !== undefined) {
      // A hub resolves findings it doesn't see, so it must only get whole-account scans.
      return { output: "error: --push scans the whole account; it can't be combined with --namespace.", exitCode: 2 };
    }
    if (!pushToken) {
      return { output: "error: --push needs a hub token. Set WULF_HUB_TOKEN.", exitCode: 2 };
    }
  }

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
  const analysis = analyzeAccount(snapshot, {
    ...(options.source ? { localSources: loadLocalSources(options.source) } : {}),
    ignore,
    severity: minSeverity,
  });
  const gaps = analysis.gaps;

  const report = buildReport(randomUUID(), new Date().toISOString(), analysis.groups, gaps);
  const all = totalFindings(report);

  const notes: string[] = [
    ...gaps.map(coverageNote),
    ...analysis.errors.map((e) => `note: rule ${e.rule_id} errored: ${e.message}`),
  ];
  if (options.save) {
    notes.push(`note: saved run report to ${saveRunReport(report, options.save)}`);
  }
  let pushFailed = false;
  if (options.push !== undefined) {
    const pushed = await pushToHub(options.push, pushToken!, startedAt, summarizeSnapshot(snapshot), pushFetch);
    pushFailed = pushed.startsWith("error:");
    notes.push(pushed);
  }

  let output: string;
  if (options.json) {
    output = renderJson(report);
  } else {
    const parts = [renderHuman(report)];
    if (notes.length > 0) parts.push("", ...notes);
    output = parts.join("\n");
  }

  // JSON output stays a pure report; a failed push still has to fail the run.
  if (options.json && pushFailed) output += `\n${notes.at(-1)}`;
  const exitCode = pushFailed ? 2 : options.strict && hasHighOrAbove(all) ? 1 : 0;
  return { output, exitCode };
}

/**
 * Send a collected scan to ScanHub as one batch. It carries the same summary the
 * hub's own Workflow stores: derived data only, no bundle text or binding values.
 */
async function pushToHub(
  hubUrl: string,
  token: string,
  startedAt: string,
  summary: AccountSummary,
  pushFetch: PushFetch,
): Promise<string> {
  const url = `${hubUrl.replace(/\/+$/, "")}/ingest/scan`;
  const batch = { scripts: summary.scripts, namespaces: summary.namespaces, coverage: summary.coverage };
  let res: Response;
  try {
    res = await pushFetch(url, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ accountId: summary.accountId, startedAt, batches: [batch] }),
    });
  } catch (err) {
    return `error: push to ${url} failed: ${(err as Error).message}`;
  }
  const text = await res.text();
  if (!res.ok) return `error: push to ${url} failed: HTTP ${res.status} ${text.slice(0, 200)}`;
  const r = JSON.parse(text) as { scan_id: string; status: string; seen: number; opened: number; reopened: number; resolved: number };
  return (
    `note: pushed to ${hubUrl} as ${r.scan_id} (${r.status}): ${r.seen} findings, ` +
    `${r.opened} new, ${r.reopened} reopened, ${r.resolved} resolved`
  );
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
