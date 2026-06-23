import type { Finding, Severity } from "./rule.js";
import { countBySeverity, sortFindings, type SeverityCounts } from "./runner.js";

export interface FindingGroup {
  kind: "config" | "source" | "account";
  /** What the findings pertain to: "wrangler.toml", "src/index.ts", "script:foo". */
  source: string;
  findings: Finding[];
}

export interface AuditReport {
  run_id: string;
  timestamp: string;
  groups: FindingGroup[];
  counts: SeverityCounts;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[1;35m", // bright magenta
  high: "\x1b[1;31m", // bright red
  medium: "\x1b[33m", // yellow
  low: "\x1b[36m", // cyan
  informational: "\x1b[90m", // grey
};
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";

function useColor(): boolean {
  return Boolean(process.stdout.isTTY) && !process.env["NO_COLOR"];
}

function color(text: string, code: string): string {
  return useColor() ? `${code}${text}${RESET}` : text;
}

/** Build the aggregate report from grouped findings. */
export function buildReport(
  runId: string,
  timestamp: string,
  groups: FindingGroup[],
): AuditReport {
  const all = groups.flatMap((g) => g.findings);
  return {
    run_id: runId,
    timestamp,
    groups: groups.map((g) => ({ ...g, findings: sortFindings(g.findings) })),
    counts: countBySeverity(all),
  };
}

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    if (line.length + word.length + 1 > width && line) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join("\n");
}

/** Human-readable grouped table (PRD §13.1). */
export function renderHuman(report: AuditReport): string {
  const out: string[] = [];
  const groupsWithFindings = report.groups.filter((g) => g.findings.length > 0);

  if (groupsWithFindings.length === 0) {
    out.push(color("No findings.", DIM));
  }

  for (const group of groupsWithFindings) {
    out.push(`${group.kind}: ${group.source}`);
    for (const f of group.findings) {
      const tag = `[${f.severity}]`.padEnd(9);
      out.push(
        `  ${color(tag, SEVERITY_COLORS[f.severity])} ${f.rule_id.padEnd(11)} ${color(f.resource, DIM)}`,
      );
      out.push(wrap(f.message, 76, "      "));
      out.push(wrap(`fix: ${f.remediation}  (probe: ${f.probe})`, 76, "      "));
      out.push("");
    }
  }

  const c = report.counts;
  const total = c.critical + c.high + c.medium + c.low + c.informational;
  out.push(
    `${total} finding(s): ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.informational} info`,
  );
  return out.join("\n");
}

/** Serializable run-result object (PRD §13.2 shape). Shared by JSON output and
 * persisted run files so `wulf report` can read back what `audit`/`scan` emit. */
export interface SerializedReport {
  run_id: string;
  timestamp: string;
  sources: { source: string; findings: Finding[] }[];
  counts: SeverityCounts;
}

export function toSerializable(report: AuditReport): SerializedReport {
  return {
    run_id: report.run_id,
    timestamp: report.timestamp,
    sources: report.groups.map((g) => ({ source: g.source, findings: g.findings })),
    counts: report.counts,
  };
}

/** Machine-readable JSON (PRD §13.2). */
export function renderJson(report: AuditReport): string {
  return JSON.stringify(toSerializable(report), null, 2);
}

export function totalFindings(report: AuditReport): Finding[] {
  return report.groups.flatMap((g) => g.findings);
}
