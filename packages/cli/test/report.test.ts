import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { runAudit } from "../src/commands/audit.js";
import { runReport } from "../src/commands/report.js";
import { aggregate } from "../src/report/aggregate.js";
import { buildMatrix, loadHarnessProbes, matchProbe } from "../src/report/matrix.js";
import { loadRunReports } from "../src/report/persist.js";

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = join(here, "fixtures", "vulnerable");
const families = join(here, "fixtures", "families");
const harnessResults = join(here, "fixtures", "probes");

const tmp = () => mkdtempSync(join(tmpdir(), "wulf-report-"));

describe("run report persistence", () => {
  it("audit --save writes a run file that report can read back", () => {
    const dir = tmp();
    runAudit([vulnerable], { source: true, save: dir });
    const files = readdirSync(dir).filter((f) => f.startsWith("wulf-"));
    expect(files).toHaveLength(1);
    const reports = loadRunReports(dir);
    expect(reports).toHaveLength(1);
    expect(reports[0]!.sources.length).toBeGreaterThan(0);
  });

  it("aggregates and dedupes findings across multiple runs", () => {
    const dir = tmp();
    // Same fixture twice → same findings; occurrences should merge.
    runAudit([vulnerable], { source: true, save: dir });
    runAudit([vulnerable], { source: true, save: dir });
    const reports = loadRunReports(dir);
    expect(reports).toHaveLength(2);
    const agg = aggregate(reports);
    expect(agg.runCount).toBe(2);
    const sample = agg.findings.find((f) => f.rule_id === "WF-BIND-01");
    expect(sample?.occurrences).toBe(2);
    // Deduped: unique (rule, resource) pairs only.
    const keys = agg.findings.map((f) => `${f.rule_id}::${f.resource}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("report command", () => {
  it("renders a markdown report with a severity summary", () => {
    const dir = tmp();
    runAudit([families], { source: true, save: dir });
    const { output, exitCode } = runReport({ resultsDir: dir });
    expect(exitCode).toBe(0);
    expect(output).toContain("# Workerwulf Scan Report");
    expect(output).toContain("| Severity | Count |");
    expect(output).toContain("WF-BUSE-01");
  });

  it("notes when no run reports exist", () => {
    const { output } = runReport({ resultsDir: tmp() });
    expect(output).toContain("No run reports found");
  });
});

describe("coverage matrix", () => {
  it("matchProbe is wildcard-aware", () => {
    expect(matchProbe("W-CAP-01", "W-CAP-*")).toBe(true);
    expect(matchProbe("W-CAP-01", "W-CAP-01")).toBe(true);
    expect(matchProbe("W-CAP-01", "F-001")).toBe(false);
    expect(matchProbe("W-CAP-01", "—")).toBe(false);
  });

  it("every registered rule has a probe back-reference (§14)", () => {
    const matrix = buildMatrix();
    expect(matrix.invalidRules).toHaveLength(0);
    expect(matrix.rules.length).toBeGreaterThan(30);
  });

  it("marks probes with no rule as explicit gaps", () => {
    const matrix = buildMatrix([
      { id: "W-CAP-01", description: "cred exposure" },
      { id: "REPLAY-09", description: "indirect injection — no static indicator" },
    ]);
    const covered = matrix.probeCoverage!.find((p) => p.probe === "W-CAP-01");
    const gap = matrix.probeCoverage!.find((p) => p.probe === "REPLAY-09");
    expect(covered!.status).toBe("covered");
    expect(covered!.rules.length).toBeGreaterThan(0);
    expect(gap!.status).toBe("gap");
    expect(gap!.rules).toHaveLength(0);
  });

  it("ingests real harness probe results", () => {
    const probes = loadHarnessProbes(harnessResults);
    expect(probes.length).toBeGreaterThan(0);
    expect(probes.every((p) => typeof p.id === "string")).toBe(true);
  });
});
