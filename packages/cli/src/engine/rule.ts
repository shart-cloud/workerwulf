import {
  allRuleProbeRefs as staticRuleProbeRefs,
  allRules as staticRules,
  type Finding,
  type RuleBase,
  type RuleSummary,
} from "@wulf/analyze";

import type { Fingerprint } from "../dast/fingerprint.js";
import type { ProbeHttp } from "../dast/http.js";

// Config, source and account rules live in @wulf/analyze (pure, also run in
// workerd). DAST probe rules make live network requests, so they stay here.
export * from "@wulf/analyze";

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
  /**
   * Suspected celld internal/operator listener (the node's `--advertise`
   * address), from `--celld-internal`. Added to scope by the command. When set,
   * the celld operator check probes it; otherwise it probes the target origin
   * only if the fingerprint already identified celld.
   */
  celldInternal?: URL;
  /** Fresh unguessable token for cache-busters and reflection markers. */
  nonce(): string;
}

export interface ProbeRule extends RuleBase {
  surface: "probe";
  check(this: ProbeRule, ctx: ProbeContext): Promise<Finding[]>;
}

const probeRules: ProbeRule[] = [];

export function registerProbe(rule: Omit<ProbeRule, "surface">): void {
  probeRules.push({ ...rule, surface: "probe" });
}

export function getProbeRules(): readonly ProbeRule[] {
  return probeRules;
}

/** All registered probe IDs, DAST rules included — used by `wulf report --matrix` validation. */
export function allRuleProbeRefs(): { id: string; probe: string }[] {
  return [...staticRuleProbeRefs(), ...probeRules.map((r) => ({ id: r.id, probe: r.probe }))];
}

/** Flat summary of every registered rule, DAST rules included, for the coverage matrix. */
export function allRules(): RuleSummary[] {
  return [
    ...staticRules(),
    ...probeRules.map((r) => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      probe: r.probe,
      family: r.family,
      surface: r.surface,
    })),
  ];
}
