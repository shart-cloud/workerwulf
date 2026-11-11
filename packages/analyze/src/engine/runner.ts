import {
  getAccountRules,
  getConfigRules,
  getSourceRules,
  SEVERITY_ORDER,
  type AccountContext,
  type ConfigContext,
  type Finding,
  type Severity,
  type SourceContext,
} from "./rule.js";

export interface RuleError {
  rule_id: string;
  message: string;
}

export interface RunOutcome {
  findings: Finding[];
  errors: RuleError[];
}

/** Run every registered config rule against a config context. */
export function runConfigRules(ctx: ConfigContext): RunOutcome {
  const findings: Finding[] = [];
  const errors: RuleError[] = [];
  for (const rule of getConfigRules()) {
    try {
      findings.push(...rule.check(ctx));
    } catch (err) {
      errors.push({ rule_id: rule.id, message: (err as Error).message });
    }
  }
  return { findings, errors };
}

/** Run every registered source rule against a source context. */
export function runSourceRules(ctx: SourceContext): RunOutcome {
  const findings: Finding[] = [];
  const errors: RuleError[] = [];
  for (const rule of getSourceRules()) {
    try {
      findings.push(...rule.check(ctx));
    } catch (err) {
      errors.push({ rule_id: rule.id, message: (err as Error).message });
    }
  }
  return { findings, errors };
}

/** Run every registered account rule against an account context. */
export function runAccountRules(ctx: AccountContext): RunOutcome {
  const findings: Finding[] = [];
  const errors: RuleError[] = [];
  for (const rule of getAccountRules()) {
    try {
      findings.push(...rule.check(ctx));
    } catch (err) {
      errors.push({ rule_id: rule.id, message: (err as Error).message });
    }
  }
  return { findings, errors };
}

/** Sort findings by severity (critical first), then rule id, then resource. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sev !== 0) return sev;
    if (a.rule_id !== b.rule_id) return a.rule_id < b.rule_id ? -1 : 1;
    return a.resource < b.resource ? -1 : a.resource > b.resource ? 1 : 0;
  });
}

export type SeverityCounts = Record<Severity, number>;

export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** True if any finding is at or above high severity (for --strict exit code). */
export function hasHighOrAbove(findings: Finding[]): boolean {
  return findings.some(
    (f) => SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER["high"],
  );
}

/** Filter findings to those at or above a minimum severity. */
export function atOrAbove(findings: Finding[], min: Severity): Finding[] {
  const threshold = SEVERITY_ORDER[min];
  return findings.filter((f) => SEVERITY_ORDER[f.severity] <= threshold);
}
