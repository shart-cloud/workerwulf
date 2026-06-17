import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const ROWS_PER_TABLE = 50;

export const wBnd05: Probe = async ({ env, runId }) => {
  const db = env.PREY_D1;
  if (!db) {
    return base({
      test_id: "W-BND-05",
      track: "worker",
      description: "D1 exfil — enumerate sqlite_master, dump tables",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: { error: "PREY_D1 binding not present" },
    });
  }

  const schema = await db
    .prepare(
      "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table','view','index') AND name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )
    .all<{ type: string; name: string; tbl_name: string; sql: string | null }>();

  const tables = (schema.results ?? []).filter((r) => r.type === "table");

  const dumps: Array<{
    table: string;
    columns: string[];
    row_count_est: number | null;
    rows: Record<string, unknown>[];
    error?: string;
  }> = [];

  for (const t of tables) {
    try {
      const countRes = await db
        .prepare(`SELECT COUNT(*) AS n FROM "${t.name.replace(/"/g, '""')}"`)
        .first<{ n: number }>();
      const rowsRes = await db
        .prepare(`SELECT * FROM "${t.name.replace(/"/g, '""')}" LIMIT ${ROWS_PER_TABLE}`)
        .all<Record<string, unknown>>();
      const rows = rowsRes.results ?? [];
      dumps.push({
        table: t.name,
        columns: rows.length > 0 ? Object.keys(rows[0]!) : [],
        row_count_est: countRes?.n ?? null,
        rows,
      });
    } catch (err) {
      dumps.push({
        table: t.name,
        columns: [],
        row_count_est: null,
        rows: [],
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const flat = JSON.stringify(dumps);
  const exfilPattern = /EXFIL-|canary|secret|password|api[-_]?key/i;
  const exfil_hits = exfilPattern.test(flat);

  return base({
    test_id: "W-BND-05",
    track: "worker",
    description: "D1 exfil — enumerate sqlite_master, dump tables",
    target: "env.PREY_D1",
    result: tables.length > 0 ? "accessible" : "informational",
    severity:
      exfil_hits ? "high" : tables.length > 0 ? "medium" : "informational",
    run_id: runId,
    details: {
      schema: schema.results ?? [],
      table_count: tables.length,
      dumps,
      exfil_hit: exfil_hits,
    },
    comparison: {
      aws_lambda: "n/a — RDS/Aurora require credentials; SQL Lambda → DB hop usually IAM-auth",
      azure_functions: "n/a — Azure SQL via connection string or managed identity",
      gcp_functions: "n/a — Cloud SQL requires IAM or password",
    },
  });
};
