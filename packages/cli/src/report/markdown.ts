import type { Severity } from "../engine/rule.js";
import type { AggregateResult } from "./aggregate.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "informational"];

/** Render aggregated findings as a Markdown report. */
export function renderMarkdown(agg: AggregateResult): string {
  const c = agg.counts;
  const total = c.critical + c.high + c.medium + c.low + c.informational;
  const lines: string[] = [
    "# Workerwulf Scan Report",
    "",
    `Aggregated from **${agg.runCount}** run(s). **${total}** unique finding(s).`,
    "",
    "| Severity | Count |",
    "|---|---|",
    `| critical | ${c.critical} |`,
    `| high | ${c.high} |`,
    `| medium | ${c.medium} |`,
    `| low | ${c.low} |`,
    `| informational | ${c.informational} |`,
    "",
  ];

  for (const severity of SEVERITY_ORDER) {
    const group = agg.findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    lines.push(`## ${severity} (${group.length})`, "");
    for (const f of group) {
      const occ = f.occurrences > 1 ? ` _(×${f.occurrences})_` : "";
      lines.push(`### ${f.rule_id} — ${f.title}${occ}`, "");
      lines.push(`- **Resource:** \`${f.resource}\``);
      lines.push(`- **Probe:** ${f.probe}  ·  **Family:** ${f.family}`);
      lines.push(`- ${f.message}`);
      lines.push(`- **Fix:** ${f.remediation}`);
      lines.push("");
    }
  }

  if (total === 0) lines.push("_No findings._", "");
  return lines.join("\n");
}

/** Render aggregated findings as JSON. */
export function renderAggregateJson(agg: AggregateResult): string {
  return JSON.stringify(agg, null, 2);
}
