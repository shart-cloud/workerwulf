import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { allRules, type RuleSummary } from "../engine/rule.js";

/** A probe id + short description, ingested from harness results. */
export interface HarnessProbe {
  id: string;
  description: string;
}

export interface ProbeCoverageRow {
  probe: string;
  weakness: string;
  rules: string[];
  status: "covered" | "gap";
}

export interface CoverageMatrix {
  rules: RuleSummary[];
  /** Present only when harness probes were ingested (--include-probes). */
  probeCoverage?: ProbeCoverageRow[];
  /** Rules whose probe field is empty (traceability violation, §14). */
  invalidRules: { id: string; reason: string }[];
}

/** Wildcard-aware probe match: rule probe "W-CAP-*" covers harness "W-CAP-01". */
export function matchProbe(harnessId: string, ruleProbe: string): boolean {
  if (ruleProbe === "—" || ruleProbe === "") return false;
  if (ruleProbe.endsWith("*")) return harnessId.startsWith(ruleProbe.slice(0, -1));
  return harnessId === ruleProbe;
}

/**
 * Build the rule × probe coverage matrix from the registered rules. With a
 * harness probe set, also computes per-probe coverage and explicit gap rows
 * (probes with no detection rule). Validates that every rule cites a probe
 * (the "—" sentinel is the documented exception, e.g. WF-DRIFT-01).
 */
export function buildMatrix(probes?: HarnessProbe[]): CoverageMatrix {
  const rules = allRules();
  const invalidRules = rules
    .filter((r) => r.probe.trim() === "")
    .map((r) => ({ id: r.id, reason: "empty probe back-reference" }));

  let probeCoverage: ProbeCoverageRow[] | undefined;
  if (probes && probes.length > 0) {
    probeCoverage = probes.map((p) => {
      const matched = rules.filter((r) => matchProbe(p.id, r.probe)).map((r) => r.id);
      return {
        probe: p.id,
        weakness: p.description,
        rules: matched,
        status: matched.length > 0 ? "covered" : "gap",
      };
    });
  }

  return { rules, probeCoverage, invalidRules };
}

/** Render the coverage matrix as Markdown. */
export function renderMatrixMarkdown(matrix: CoverageMatrix): string {
  const lines: string[] = ["# Rule × Probe Coverage Matrix", ""];

  lines.push("## Rule → Probe Traceability", "");
  lines.push("| Rule | Probe | Family | Surface | Title |");
  lines.push("|---|---|---|---|---|");
  for (const r of matrix.rules) {
    lines.push(`| ${r.id} | ${r.probe} | ${r.family} | ${r.surface} | ${mdCell(r.title)} |`);
  }
  lines.push("");

  if (matrix.probeCoverage) {
    const covered = matrix.probeCoverage.filter((p) => p.status === "covered").length;
    const gaps = matrix.probeCoverage.length - covered;
    lines.push("## Probe Coverage", "");
    lines.push(`${covered} covered, ${gaps} gap(s).`, "");
    lines.push("| Probe | Weakness | Detection Rule | Status |");
    lines.push("|---|---|---|---|");
    for (const p of matrix.probeCoverage) {
      const rule = p.rules.length > 0 ? p.rules.join(", ") : "—";
      lines.push(`| ${p.probe} | ${mdCell(p.weakness)} | ${rule} | ${p.status} |`);
    }
    lines.push("");
  }

  if (matrix.invalidRules.length > 0) {
    lines.push("## ⚠ Traceability Violations", "");
    for (const v of matrix.invalidRules) lines.push(`- ${v.id}: ${v.reason}`);
    lines.push("");
  }

  return lines.join("\n");
}

/** Escape a value for use inside a Markdown table cell. */
function mdCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

/**
 * Ingest harness probe results (ProbeResult JSON: single object or array per
 * file) from a directory or a single file, returning unique {id, description}.
 */
export function loadHarnessProbes(path: string): HarnessProbe[] {
  const files: string[] = [];
  const st = statSync(path);
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name.endsWith(".json")) files.push(join(path, name));
    }
  } else {
    files.push(path);
  }

  const byId = new Map<string, HarnessProbe>();
  for (const file of files) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    const records = Array.isArray(parsed) ? parsed : [parsed];
    for (const rec of records) {
      const r = rec as { test_id?: unknown; description?: unknown };
      if (typeof r.test_id !== "string") continue;
      if (!byId.has(r.test_id)) {
        byId.set(r.test_id, {
          id: r.test_id,
          description: typeof r.description === "string" ? r.description : "",
        });
      }
    }
  }
  return [...byId.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}
