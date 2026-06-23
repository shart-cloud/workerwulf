import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { AuditReport, SerializedReport } from "../engine/output.js";
import { toSerializable } from "../engine/output.js";

/** Persist a run's report as <dir>/wulf-<run_id>.json and return the path. */
export function saveRunReport(report: AuditReport, dir: string): string {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const path = join(dir, `wulf-${report.run_id}.json`);
  writeFileSync(path, JSON.stringify(toSerializable(report), null, 2));
  return path;
}

/** Load persisted run reports from a results directory. */
export function loadRunReports(dir: string, runId?: string): SerializedReport[] {
  if (!existsSync(dir)) return [];
  const out: SerializedReport[] = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith(".json")) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch {
      continue; // skip malformed files
    }
    if (!isSerializedReport(parsed)) continue;
    if (runId && parsed.run_id !== runId) continue;
    out.push(parsed);
  }
  return out;
}

function isSerializedReport(value: unknown): value is SerializedReport {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as SerializedReport).run_id === "string" &&
    Array.isArray((value as SerializedReport).sources)
  );
}
