import type { Finding, RuleError, RunOutcome } from "@wulf/analyze";

import { getProbeRules, type ProbeContext } from "./rule.js";

export * from "@wulf/analyze";

/**
 * Run every registered probe rule sequentially (never in parallel — the
 * client's rate limit and budget assume one request in flight). A budget
 * exhaustion stops the remaining rules; any other error is recorded per rule.
 */
export async function runProbeRules(
  ctx: ProbeContext,
  skip: (ruleId: string) => boolean,
  isFatal: (err: unknown) => boolean,
): Promise<RunOutcome> {
  const findings: Finding[] = [];
  const errors: RuleError[] = [];
  for (const rule of getProbeRules()) {
    if (skip(rule.id)) continue;
    try {
      findings.push(...(await rule.check(ctx)));
    } catch (err) {
      errors.push({ rule_id: rule.id, message: (err as Error).message });
      if (isFatal(err)) break;
    }
  }
  return { findings, errors };
}
