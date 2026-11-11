import type { Finding, Severity } from "@wulf/core";

import type { BindingMap } from "../ast/binding-map.js";
import type { ProjectFiles } from "./files.js";
import type { SourceFile } from "../ast/parse.js";
import type { DeclaredBinding } from "../parsers/bindings.js";
import type { WranglerConfig } from "../parsers/wrangler.js";

// The finding contract is owned by @wulf/core (Effect Schema), shared with the
// platform hub and the research harness.
export { SEVERITY_ORDER, type Evidence, type Finding, type Severity } from "@wulf/core";

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
  /** Files next to the config, for supply-chain rules. Those rules skip when absent. */
  files?: ProjectFiles;
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

const configRules: ConfigRule[] = [];
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
  return [...configRules, ...sourceRules, ...accountRules].map((r) => ({
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
  surface: "config" | "source" | "account";
}

/** Flat summary of every registered rule, for the coverage matrix. */
export function allRules(): RuleSummary[] {
  return [...configRules, ...sourceRules, ...accountRules].map((r) => ({
    id: r.id,
    title: r.title,
    severity: r.severity,
    probe: r.probe,
    family: r.family,
    surface: r.surface,
  }));
}
