import { randomBytes, randomUUID } from "node:crypto";

import { fingerprint } from "../dast/fingerprint.js";
import {
  BudgetExceededError,
  FetchHttpClient,
  OutOfScopeError,
  ProbeHttp,
  type HttpClient,
} from "../dast/http.js";
import { inScope, loadScopeFile, mergeScopes, parseScope, type Scope } from "../dast/scope.js";
import { buildReport, renderHuman, renderJson, totalFindings } from "../engine/output.js";
import { getProbeRules, type Finding, type ProbeContext, type Severity } from "../engine/rule.js";
import { atOrAbove, hasHighOrAbove, runProbeRules } from "../engine/runner.js";
import { saveRunReport } from "../report/persist.js";
import "../rules/index.js";

export interface ProbeOptions {
  /** Path to a scope file (one host or *.host per line). */
  scope?: string;
  /** Comma-separated hosts to allow, in addition to --scope. */
  allow?: string;
  /** Extra same-origin paths to test (comma-separated). */
  paths?: string;
  /** Fingerprint only — skip every active vulnerability check. */
  passive?: boolean;
  /** "Name: value" credential header for the authenticated cache differential. */
  authHeader?: string;
  /** Suspected celld internal/operator listener URL (host auto-added to scope). */
  celldInternal?: string;
  /** Permit POST requests with malformed bodies (off by default). */
  allowPost?: boolean;
  rps?: number;
  maxRequests?: number;
  timeoutMs?: number;
  json?: boolean;
  strict?: boolean;
  severity?: Severity;
  ignore?: string;
  save?: string;
  userAgent?: string;
}

export interface ProbeRunResult {
  output: string;
  exitCode: number;
}

const DEFAULT_UA = "wulf-dast/0.1 (workerwulf research scanner)";
const PASSIVE_RULES = new Set(["WF-DAST-FP-01", "WF-DAST-ACCESS-01"]);

/**
 * Black-box scan of one Worker URL. `clientOverride` swaps the network
 * transport (tests); scope, pacing and the request budget are always enforced.
 */
export async function runProbe(
  rawTarget: string,
  options: ProbeOptions,
  clientOverride?: HttpClient,
): Promise<ProbeRunResult> {
  let target: URL;
  try {
    target = new URL(rawTarget);
  } catch {
    return { output: `error: invalid target URL "${rawTarget}"`, exitCode: 2 };
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return { output: `error: target must be http(s): "${rawTarget}"`, exitCode: 2 };
  }

  let celldInternal: URL | undefined;
  if (options.celldInternal) {
    try {
      celldInternal = new URL(options.celldInternal);
    } catch {
      return { output: `error: --celld-internal must be a URL`, exitCode: 2 };
    }
  }

  // Scope. The target host (and the celld-internal host, which is the same node)
  // are implicitly in scope; everything else must be listed in --scope or
  // --allow. This is the authorization gate: without a valid in-scope target the
  // scanner refuses to send a single request.
  let scope: Scope;
  try {
    scope = buildScope(target, options, celldInternal);
  } catch (err) {
    return { output: `error: ${(err as Error).message}`, exitCode: 2 };
  }
  if (!inScope(scope, target.toString())) {
    return {
      output:
        `error: target ${target.hostname} is not in scope. Add it with --allow ${target.hostname} ` +
        "or a --scope file. Only scan hosts you are authorized to test.",
      exitCode: 2,
    };
  }

  const auth = parseAuthHeader(options.authHeader);
  if (options.authHeader && !auth) {
    return { output: `error: --auth-header must be "Name: value"`, exitCode: 2 };
  }

  const client: HttpClient =
    clientOverride ?? new FetchHttpClient(options.timeoutMs ?? 10_000, options.userAgent ?? DEFAULT_UA);
  const http = new ProbeHttp(client, {
    scope,
    maxRequests: options.maxRequests ?? 300,
    rps: options.rps ?? 5,
  });

  const nonce = (): string => randomBytes(6).toString("hex");

  let fp;
  try {
    fp = await fingerprint(http, target, nonce);
  } catch (err) {
    if (err instanceof OutOfScopeError) return { output: `error: ${err.message}`, exitCode: 2 };
    return { output: `error: could not reach ${target.hostname}: ${(err as Error).message}`, exitCode: 2 };
  }

  const ctx: ProbeContext = {
    target,
    http,
    fingerprint: fp,
    paths: dedupePaths(["/", target.pathname, ...parseList(options.paths)]),
    auth,
    allowPost: Boolean(options.allowPost),
    celldInternal,
    nonce,
  };

  const skip = (ruleId: string): boolean => Boolean(options.passive) && !PASSIVE_RULES.has(ruleId);
  const outcome = await runProbeRules(ctx, skip, (err) => err instanceof BudgetExceededError);

  const minSeverity: Severity = options.severity ?? "informational";
  const ignore = new Set(parseList(options.ignore));
  const kept = atOrAbove(
    outcome.findings.filter((f) => !ignore.has(f.rule_id)),
    minSeverity,
  );

  const report = buildReport(randomUUID(), new Date().toISOString(), [
    { kind: "probe", source: `target:${target.origin}`, findings: kept },
  ]);

  const notes: string[] = [
    `scanned ${target.origin} — ${http.used} request(s), platform ${fp.platform} (${fp.confidence} confidence)` +
      (fp.colo ? `, colo ${fp.colo}` : ""),
    ...outcome.errors.map((e) => `note: rule ${e.rule_id} stopped: ${e.message}`),
  ];
  if (options.save) notes.push(`note: saved run report to ${saveRunReport(report, options.save)}`);

  const output = options.json ? renderJson(report) : [renderHuman(report), "", ...notes].join("\n");
  const exitCode = options.strict && hasHighOrAbove(totalFindings(report)) ? 1 : 0;
  return { output, exitCode };
}

function buildScope(target: URL, options: ProbeOptions, celldInternal?: URL): Scope {
  const scopes: Scope[] = [parseScope([target.hostname])];
  if (celldInternal) scopes.push(parseScope([celldInternal.hostname]));
  if (options.scope) scopes.push(loadScopeFile(options.scope));
  if (options.allow) scopes.push(parseScope(parseList(options.allow)));
  return mergeScopes(...scopes);
}

function parseAuthHeader(raw?: string): { name: string; value: string } | undefined {
  if (!raw) return undefined;
  const idx = raw.indexOf(":");
  if (idx <= 0) return undefined;
  return { name: raw.slice(0, idx).trim(), value: raw.slice(idx + 1).trim() };
}

function parseList(raw?: string): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function dedupePaths(paths: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of paths) {
    const path = p.startsWith("/") ? p : `/${p}`;
    if (seen.has(path)) continue;
    seen.add(path);
    out.push(path);
  }
  return out;
}
