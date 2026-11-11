import type { SerializedReport } from "../engine/output.js";
import { countBySeverity, sortFindings, type Finding, type SeverityCounts } from "@wulf/analyze";

export interface AggregatedFinding extends Finding {
  /** How many times this (rule, resource) appeared across the loaded runs. */
  occurrences: number;
  /** Run IDs the finding appeared in. */
  runs: string[];
}

export interface AggregateResult {
  runCount: number;
  findings: AggregatedFinding[];
  counts: SeverityCounts;
}

/**
 * Aggregate findings across persisted run reports, deduplicated by
 * (rule_id, resource). The first occurrence supplies the finding detail;
 * occurrence count and contributing run IDs are tracked for the report.
 */
export function aggregate(reports: SerializedReport[]): AggregateResult {
  const byKey = new Map<string, AggregatedFinding>();
  for (const report of reports) {
    for (const source of report.sources) {
      for (const finding of source.findings) {
        const key = `${finding.rule_id}::${finding.resource}`;
        const existing = byKey.get(key);
        if (existing) {
          existing.occurrences++;
          if (!existing.runs.includes(report.run_id)) existing.runs.push(report.run_id);
        } else {
          byKey.set(key, { ...finding, occurrences: 1, runs: [report.run_id] });
        }
      }
    }
  }
  const findings = sortFindings([...byKey.values()]) as AggregatedFinding[];
  return {
    runCount: reports.length,
    findings,
    counts: countBySeverity(findings),
  };
}
