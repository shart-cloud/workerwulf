import type { AccountSnapshot, Coverage, RawBinding } from "@wulf/core";

import { buildBindingMap } from "./ast/binding-map.js";
import { parse, type SourceFile } from "./ast/parse.js";
import type { FindingGroup } from "./engine/report.js";
import type { AccountContext, Finding, ScriptMetadata, Severity, WfPNamespace } from "./engine/rule.js";
import { atOrAbove, runAccountRules, type RuleError } from "./engine/runner.js";
import type { BindingType, DeclaredBinding } from "./parsers/bindings.js";

/**
 * Map a Cloudflare API binding `type` to a capability BindingType. Returns
 * undefined for non-capability bindings (plain_text, json, wasm_module, ...),
 * which carry no blast radius.
 */
const API_BINDING_TYPES: Record<string, BindingType> = {
  kv_namespace: "kv_namespace",
  r2_bucket: "r2_bucket",
  d1: "d1_database",
  d1_database: "d1_database",
  hyperdrive: "hyperdrive",
  service: "service",
  queue: "queue_producer",
  browser: "browser",
  browser_rendering: "browser",
  ai: "ai",
  vectorize: "vectorize",
  mtls_certificate: "mtls_certificate",
  send_email: "send_email",
  analytics_engine: "analytics_engine",
  secret_text: "secret",
  secrets_store_secret: "secret",
  dispatch_namespace: "dispatch_namespace",
  durable_object_namespace: "durable_object",
};

export function mapApiBinding(raw: RawBinding): DeclaredBinding | undefined {
  const type = API_BINDING_TYPES[raw.type];
  if (!type) return undefined;
  return { type, name: raw.name, configKey: `binding:${raw.name}` };
}

export interface AccountAnalysisOptions {
  /** Local source per deployed script name, for drift rules. */
  localSources?: ReadonlyMap<string, SourceFile>;
  /** Rule IDs to drop. */
  ignore?: ReadonlySet<string>;
  /** Minimum severity to keep; `wulf scan` defaults to "low". */
  severity?: Severity;
}

export interface AccountAnalysis {
  groups: FindingGroup[];
  /** Reads that did not complete, from the snapshot's coverage. */
  gaps: Coverage[];
  errors: RuleError[];
}

/**
 * Run every account rule over a collected snapshot. Pure: no API calls, so
 * the CLI and a Worker given the same snapshot produce the same groups.
 */
export function analyzeAccount(
  snapshot: AccountSnapshot,
  options: AccountAnalysisOptions = {},
): AccountAnalysis {
  const ctx = accountContext(snapshot, options.localSources);
  const outcome = runAccountRules(ctx);
  const ignore = options.ignore ?? new Set<string>();
  const kept = outcome.findings.filter((f) => !ignore.has(f.rule_id));
  const min = options.severity ?? "low";
  const groups = groupByResource(kept).map((g) => ({ ...g, findings: atOrAbove(g.findings, min) }));
  return {
    groups,
    gaps: snapshot.coverage.filter((c) => c.status !== "complete"),
    errors: outcome.errors,
  };
}

/**
 * Shape a collected snapshot into the rules' AccountContext. A read that didn't
 * complete becomes an empty value here (the rules expect arrays); the
 * snapshot's coverage records that those rules ran on partial data.
 */
export function accountContext(
  snapshot: AccountSnapshot,
  localSources?: ReadonlyMap<string, SourceFile>,
): AccountContext {
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

  return {
    accountId: snapshot.accountId,
    scripts,
    namespaces,
    localSources: localSources ? new Map(localSources) : undefined,
  };
}

/** Bucket findings into FindingGroups by their resource prefix (script:/namespace:). */
export function groupByResource(findings: Finding[]): FindingGroup[] {
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
