import type { Severity } from "@wulf/analyze";
import type { AuditReport } from "@wulf/analyze";

export {
  buildReport,
  renderJson,
  toSerializable,
  totalFindings,
  type AuditReport,
  type FindingGroup,
  type SerializedReport,
} from "@wulf/analyze";

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
