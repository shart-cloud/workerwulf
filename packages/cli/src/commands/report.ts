import { writeFileSync } from "node:fs";

import { aggregate } from "../report/aggregate.js";
import { renderAggregateJson, renderMarkdown } from "../report/markdown.js";
import {
  buildMatrix,
  loadHarnessProbes,
  renderMatrixMarkdown,
  type HarnessProbe,
} from "../report/matrix.js";
import { loadRunReports } from "../report/persist.js";
import "../rules/index.js";

export interface ReportOptions {
  resultsDir?: string;
  runId?: string;
  format?: "markdown" | "json";
  output?: string;
  matrix?: boolean;
  includeProbes?: string;
}

export interface ReportRunResult {
  output: string;
  exitCode: number;
}

/**
 * Aggregate persisted run reports into a publishable report. With --matrix,
 * renders the rule × probe coverage matrix (and validates traceability, §14);
 * with --include-probes, the matrix gains explicit gap rows for harness probes
 * that no rule detects.
 */
export function runReport(options: ReportOptions): ReportRunResult {
  const format = options.format ?? "markdown";
  const sections: string[] = [];
  let exitCode = 0;

  if (options.matrix) {
    let probes: HarnessProbe[] | undefined;
    if (options.includeProbes) {
      try {
        probes = loadHarnessProbes(options.includeProbes);
      } catch (err) {
        return { output: `error: ${(err as Error).message}`, exitCode: 2 };
      }
    }
    const matrix = buildMatrix(probes);
    sections.push(format === "json" ? JSON.stringify(matrix, null, 2) : renderMatrixMarkdown(matrix));
    // §14: a rule with no probe back-reference is a traceability violation.
    if (matrix.invalidRules.length > 0) exitCode = 1;
  } else {
    const resultsDir = options.resultsDir ?? "./results";
    const reports = loadRunReports(resultsDir, options.runId);
    const agg = aggregate(reports);
    if (reports.length === 0) {
      sections.push(
        format === "json"
          ? renderAggregateJson(agg)
          : `_No run reports found in ${resultsDir}. Run \`wulf audit . --save ${resultsDir}\` first._`,
      );
    } else {
      sections.push(format === "json" ? renderAggregateJson(agg) : renderMarkdown(agg));
    }
  }

  const output = sections.join("\n");
  if (options.output) {
    writeFileSync(options.output, output + "\n");
    return { output: `wrote report to ${options.output}`, exitCode };
  }
  return { output, exitCode };
}
