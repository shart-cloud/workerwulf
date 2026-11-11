import type { BindingMap } from "../ast/binding-map.js";
import type { SourceFile } from "../ast/parse.js";
import type { DeclaredBinding } from "../parsers/bindings.js";
import type { WranglerConfig } from "../parsers/wrangler.js";
import type { Fingerprint } from "../dast/fingerprint.js";
import type { ProbeHttp } from "../dast/http.js";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

export interface Evidence {
  type: "config" | "source" | "binding" | "api" | "http";
  label: string;
  /** Short inline text payload. */
  inline?: string;
  /** Relative path to a larger artifact. */
  file?: string;
}

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  /** "wrangler.toml", "src/index.ts:42", "script:prey-worker", etc. */
  resource: string;
  /** What's wrong and why. */
  message: string;
  /** How to fix. */
  remediation: string;
  /** Back-reference: "W-CAP-01", "F-002", etc. */
  probe: string;
  /** RULES_PRD family: "A".."H". */
  family: string;
  evidence?: Evidence[];
}

interface RuleBase {
  id: string;
  title: string;
  severity: Severity;
  /** Which workerwulf probe/finding empirically demonstrated this weakness. */
  probe: string;
  /** Rule family from RULES_PRD.md (A–H). */
  family: string;
}

/** Offline config context — parsed wrangler.toml, no network. */
export interface ConfigContext {
  config: WranglerConfig;
  configPath: string;
  /** Environment name this config resolves to ("default" or [env.NAME]). */
  envName: string;
}

/** Source analysis context — AST + binding map from a single parse pass. */
export interface SourceContext {
  config: WranglerConfig;
  configPath: string;
  source: SourceFile;
  bindingMap: BindingMap;
}

/** A route pattern bound to a deployed script. */
export interface RouteInfo {
  pattern: string;
}

/** A deployed script's metadata, enriched with its parsed binding usage. */
export interface ScriptMetadata {
  name: string;
  /** Bindings declared on the deployed script (from the API). */
  declared: DeclaredBinding[];
  routes: RouteInfo[];
  /** Downloaded bundle text, if available. */
  content?: string;
  /** Binding usage parsed from the downloaded bundle, if available. */
  bindingMap?: BindingMap;
}

/** A Workers-for-Platforms dispatch namespace, normalized from the API. */
export interface WfPNamespace {
  name: string;
  trusted: boolean;
  hasOutbound: boolean;
  hasLimits: boolean;
  scripts: { name: string; untrusted: boolean }[];
}

/** Live scan context — populated from the Cloudflare API. */
export interface AccountContext {
  accountId: string;
  scripts: ScriptMetadata[];
  namespaces: WfPNamespace[];
  /** Local source per script name, for drift comparison (if --source given). */
  localSources?: Map<string, SourceFile>;
}

/** Black-box DAST context — a scoped HTTP client plus the target fingerprint. */
export interface ProbeContext {
  target: URL;
  /** Scope-enforcing, rate-limited, budgeted client. Every request goes through it. */
  http: ProbeHttp;
  fingerprint: Fingerprint;
  /** Same-origin paths under test: "/" plus any --path values. */
  paths: string[];
  /** Optional credential header for authenticated-vs-anonymous differentials. */
  auth?: { name: string; value: string };
  /** Permit POST requests carrying malformed bodies (off by default). */
  allowPost: boolean;
  /** Fresh unguessable token for cache-busters and reflection markers. */
  nonce(): string;
}

export interface ConfigRule extends RuleBase {
  surface: "config";
  check(this: ConfigRule, ctx: ConfigContext): Finding[];
}

export interface SourceRule extends RuleBase {
  surface: "source";
  check(this: SourceRule, ctx: SourceContext): Finding[];
}

export interface AccountRule extends RuleBase {
  surface: "account";
  check(this: AccountRule, ctx: AccountContext): Finding[];
}

export interface ProbeRule extends RuleBase {
  surface: "probe";
  check(this: ProbeRule, ctx: ProbeContext): Promise<Finding[]>;
}

const configRules: ConfigRule[] = [];
const probeRules: ProbeRule[] = [];
const sourceRules: SourceRule[] = [];
const accountRules: AccountRule[] = [];

export function registerConfig(rule: Omit<ConfigRule, "surface">): void {
  configRules.push({ ...rule, surface: "config" });
}

export function registerSource(rule: Omit<SourceRule, "surface">): void {
  sourceRules.push({ ...rule, surface: "source" });
}

export function registerAccount(rule: Omit<AccountRule, "surface">): void {
  accountRules.push({ ...rule, surface: "account" });
}

export function registerProbe(rule: Omit<ProbeRule, "surface">): void {
  probeRules.push({ ...rule, surface: "probe" });
}

export function getProbeRules(): readonly ProbeRule[] {
  return probeRules;
}

export function getConfigRules(): readonly ConfigRule[] {
  return configRules;
}

export function getSourceRules(): readonly SourceRule[] {
  return sourceRules;
}

export function getAccountRules(): readonly AccountRule[] {
  return accountRules;
}

/** All registered probe IDs — used by `wulf report --matrix` validation. */
export function allRuleProbeRefs(): { id: string; probe: string }[] {
  return [...configRules, ...sourceRules, ...accountRules, ...probeRules].map((r) => ({
    id: r.id,
    probe: r.probe,
  }));
}

export interface RuleSummary {
  id: string;
  title: string;
  severity: Severity;
  probe: string;
  family: string;
  surface: "config" | "source" | "account" | "probe";
}

/** Flat summary of every registered rule, for the coverage matrix. */
export function allRules(): RuleSummary[] {
  return [...configRules, ...sourceRules, ...accountRules, ...probeRules].map((r) => ({
    id: r.id,
    title: r.title,
    severity: r.severity,
    probe: r.probe,
    family: r.family,
    surface: r.surface,
  }));
}
