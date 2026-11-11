import type { Coverage } from "@wulf/core";

import type { Finding } from "./rule.js";
import { countBySeverity, sortFindings, type SeverityCounts } from "./runner.js";

export interface FindingGroup {
  kind: "config" | "source" | "account" | "probe";
  /** What the findings pertain to: "wrangler.toml", "src/index.ts", "script:foo". */
  source: string;
  findings: Finding[];
}

export interface AuditReport {
  run_id: string;
  timestamp: string;
  groups: FindingGroup[];
  counts: SeverityCounts;
  /** Live scans only: reads that did not complete. Absent for offline audits. */
  coverage?: Coverage[];
}

/** Build the aggregate report from grouped findings. */
export function buildReport(
  runId: string,
  timestamp: string,
  groups: FindingGroup[],
  coverage?: Coverage[],
): AuditReport {
  const all = groups.flatMap((g) => g.findings);
  return {
    run_id: runId,
    timestamp,
    groups: groups.map((g) => ({ ...g, findings: sortFindings(g.findings) })),
    counts: countBySeverity(all),
    ...(coverage && { coverage }),
  };
}

/** Serializable run-result object (PRD §13.2 shape). Shared by JSON output and
 * persisted run files so `wulf report` can read back what `audit`/`scan` emit. */
export interface SerializedReport {
  run_id: string;
  timestamp: string;
  sources: { source: string; findings: Finding[] }[];
  counts: SeverityCounts;
  /** Reads that did not complete during a live scan. */
  coverage?: Coverage[];
}

export function toSerializable(report: AuditReport): SerializedReport {
  return {
    run_id: report.run_id,
    timestamp: report.timestamp,
    sources: report.groups.map((g) => ({ source: g.source, findings: g.findings })),
    counts: report.counts,
    ...(report.coverage && { coverage: report.coverage }),
  };
}

/** Machine-readable JSON (PRD §13.2). */
export function renderJson(report: AuditReport): string {
  return JSON.stringify(toSerializable(report), null, 2);
}

export function totalFindings(report: AuditReport): Finding[] {
  return report.groups.flatMap((g) => g.findings);
}
