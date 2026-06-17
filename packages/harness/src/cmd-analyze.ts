import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { DuckDBInstance } from "@duckdb/node-api";

export async function cmdAnalyze(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      "results-dir": { type: "string", default: "results" },
      output: { type: "string" },
      "run-id": { type: "string" },
    },
  });

  const resultsDir = resolve(values["results-dir"] ?? "results");
  const runFilter = values["run-id"];
  const glob = `${resultsDir}/*/*.json`;

  const instance = await DuckDBInstance.create(":memory:");
  const conn = await instance.connect();

  // Stage 1: load every probe result file as a row.
  await conn.run(`
    CREATE TABLE probes AS
    SELECT *, filename AS _file
    FROM read_json('${escapeSql(glob)}',
                   union_by_name = true,
                   filename = true,
                   ignore_errors = true);
  `);
  await conn.run("DELETE FROM probes WHERE test_id IS NULL");
  await conn.run("ALTER TABLE probes ADD COLUMN IF NOT EXISTS error VARCHAR");
  await conn.run("ALTER TABLE probes ADD COLUMN IF NOT EXISTS message VARCHAR");
  // `tags` may be absent entirely if no probe in the result set carries it.
  await conn.run("ALTER TABLE probes ADD COLUMN IF NOT EXISTS tags VARCHAR[]");
  await conn.run(`
    UPDATE probes
    SET run_id = regexp_extract(_file, '/([^/]+)/[^/]+\\.json$', 1)
    WHERE run_id IS NULL OR run_id = '';
  `);
  await conn.run(`
    UPDATE probes
    SET result = 'error'
    WHERE result IS NULL;
  `);
  await conn.run(`
    UPDATE probes
    SET track = CASE
      WHEN starts_with(test_id, 'DO-') THEN 'durable'
      WHEN starts_with(test_id, 'AI-') THEN 'ai'
      WHEN starts_with(test_id, 'D-') THEN 'dynamic'
      WHEN starts_with(test_id, 'P-') THEN 'platform'
      ELSE 'worker'
    END
    WHERE track IS NULL OR track = '';
  `);
  await conn.run(`
    UPDATE probes
    SET description = COALESCE(description, message, error, 'Probe failed before it could return a structured result')
    WHERE description IS NULL OR description = '';
  `);
  await conn.run(`
    UPDATE probes
    SET severity = COALESCE(severity, 'informational')
    WHERE severity IS NULL OR severity = '';
  `);

  const where = runFilter ? `WHERE run_id = '${escapeSql(runFilter)}'` : "";
  const comparisonWhere = runFilter
    ? `WHERE run_id = '${escapeSql(runFilter)}' AND comparison IS NOT NULL`
    : "WHERE comparison IS NOT NULL";
  const aiModelWhere = runFilter
    ? `WHERE run_id = '${escapeSql(runFilter)}' AND test_id = 'AI-INJ-10'`
    : "WHERE test_id = 'AI-INJ-10'";
  const qualityWhere = runFilter
    ? `WHERE run_id = '${escapeSql(runFilter)}' AND (`
    : "WHERE (";

  const overall = await rows(
    conn,
    `SELECT result, COUNT(*) AS n
     FROM probes ${where}
     GROUP BY result ORDER BY n DESC`,
  );

  const byTrack = await rows(
    conn,
    `SELECT track, result, COUNT(*) AS n
     FROM probes ${where}
     GROUP BY track, result ORDER BY track, n DESC`,
  );

  const latest = await rows(
    conn,
    `WITH ranked AS (
       SELECT test_id, track, description, result, severity, run_id, timestamp,
              ROW_NUMBER() OVER (PARTITION BY test_id ORDER BY timestamp DESC) AS rk
       FROM probes ${where}
     )
     SELECT test_id, track, description, result, severity, run_id, timestamp
     FROM ranked WHERE rk = 1
     ORDER BY track, test_id`,
  );

  const comparison = await rows(
    conn,
    `SELECT test_id,
            description,
            COALESCE(result, '') AS cf_workers,
            comparison.aws_lambda AS aws_lambda,
            comparison.azure_functions AS azure_functions,
            comparison.gcp_functions AS gcp_functions
     FROM probes
      ${comparisonWhere}
      ORDER BY test_id`,
  );

  const runs = await rows(
    conn,
    `SELECT run_id, MIN(timestamp) AS started, MAX(timestamp) AS ended, COUNT(*) AS n
     FROM probes ${where}
     GROUP BY run_id ORDER BY ended DESC`,
  );

  // Cross-cutting "misconfig" slice: probes tagged with the operator-
  // misconfiguration theme, regardless of which track they live in.
  const misconfig = await rows(
    conn,
    `WITH ranked AS (
       SELECT test_id, track, result, severity, description, tags,
              ROW_NUMBER() OVER (PARTITION BY test_id ORDER BY timestamp DESC) AS rk
       FROM probes ${where}
     )
     SELECT test_id, track, result, severity, description,
            array_to_string(tags, ', ') AS tags
     FROM ranked
     WHERE rk = 1 AND tags IS NOT NULL AND list_contains(tags, 'misconfig')
     ORDER BY
       CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                     WHEN 'low' THEN 3 ELSE 4 END,
       track, test_id`,
  );

  const aiModelRows = await rows(
    conn,
    `SELECT test_id,
            details->>'$.payload' AS payload,
            details->>'$.prompt_tier' AS prompt_tier,
            details->>'$.verdict' AS verdict,
            details->>'$.model' AS model,
            COALESCE(result, '') AS result
     FROM probes
     ${aiModelWhere}
     ORDER BY test_id`,
  );

  const qualityWarnings = await rows(
    conn,
    `SELECT test_id,
            CASE
              WHEN result = 'error' THEN 'Probe failed or returned malformed/non-JSON response; counted as error.'
              WHEN test_id = 'W-NET-02' AND result = 'accessible' THEN 'Verify details.metadata_retrieved before citing metadata access.'
              WHEN test_id = 'AI-INJ-14' THEN 'Check gate_config.scan_trace: log/pass modes are observability only, not enforcing gates.'
              ELSE NULL
            END AS warning
     FROM probes
     ${qualityWhere}
        result = 'error'
        OR test_id = 'W-NET-02'
        OR test_id = 'AI-INJ-14'
      )
     ORDER BY test_id`,
  );

  const md = renderMarkdown({
    resultsDir,
    runFilter,
    overall,
    byTrack,
    latest,
    comparison,
    runs,
    misconfig,
    aiModelSummary: aiModelRows,
    qualityWarnings: qualityWarnings.filter((r) => r.warning),
  });

  if (values.output) {
    const out = resolve(values.output);
    await writeFile(out, md);
    process.stderr.write(`report → ${out}\n`);
  } else {
    process.stdout.write(md);
  }

  await conn.disconnectSync?.();
}

type Row = Record<string, unknown>;

async function rows(
  conn: Awaited<ReturnType<Awaited<ReturnType<typeof DuckDBInstance.create>>["connect"]>>,
  sql: string,
): Promise<Row[]> {
  const reader = await conn.runAndReadAll(sql);
  return reader.getRowObjectsJson() as Row[];
}

function escapeSql(s: string): string {
  return s.replace(/'/g, "''");
}

function renderMarkdown(d: {
  resultsDir: string;
  runFilter: string | undefined;
  overall: Row[];
  byTrack: Row[];
  latest: Row[];
  comparison: Row[];
  runs: Row[];
  misconfig?: Row[];
  aiModelSummary?: Row[];
  qualityWarnings?: Row[];
}): string {
  const lines: string[] = [];
  lines.push("# wulf — Findings Report");
  lines.push("");
  lines.push(`- Generated: \`${new Date().toISOString()}\``);
  lines.push(`- Results dir: \`${d.resultsDir}\``);
  if (d.runFilter) lines.push(`- Filtered to run: \`${d.runFilter}\``);
  lines.push("");

  lines.push("## Runs");
  lines.push("");
  lines.push(table(["run_id", "started", "ended", "n"], d.runs));
  lines.push("");

  lines.push("## Verdicts (overall)");
  lines.push("");
  lines.push(table(["result", "n"], d.overall));
  lines.push("");

  lines.push("## Verdicts by track");
  lines.push("");
  lines.push(table(["track", "result", "n"], d.byTrack));
  lines.push("");

  lines.push("## Latest verdict per test");
  lines.push("");
  lines.push(
    table(
      ["test_id", "track", "result", "severity", "description"],
      d.latest,
    ),
  );
  lines.push("");

  lines.push("## Comparison matrix");
  lines.push("");
  lines.push(
    "Probes that carry a `comparison` field declare expected behavior on container-based FaaS platforms. CF Workers result is the empirical reading from this run.",
  );
  lines.push("");
  lines.push(
    table(
      ["test_id", "cf_workers", "aws_lambda", "azure_functions", "gcp_functions", "description"],
      d.comparison,
    ),
  );
  lines.push("");
  if (d.misconfig && d.misconfig.length > 0) {
    lines.push("## Misconfiguration findings (cross-cutting)");
    lines.push("");
    lines.push(
      "Probes tagged `misconfig` study operator misconfiguration — the developer-created blast radius, independent of any platform bug. This slice spans tracks.",
    );
    lines.push("");
    lines.push(
      table(
        ["test_id", "track", "result", "severity", "tags", "description"],
        d.misconfig,
      ),
    );
    lines.push("");
  }
  if (d.aiModelSummary && d.aiModelSummary.length > 0) {
    lines.push("## AI Model Injection Comparison");
    lines.push("");
    lines.push(table(["test_id", "payload", "model", "prompt_tier", "verdict", "result"], d.aiModelSummary));
    lines.push("");
  }
  if (d.qualityWarnings && d.qualityWarnings.length > 0) {
    lines.push("## Data Quality Notes");
    lines.push("");
    lines.push(table(["test_id", "warning"], d.qualityWarnings));
    lines.push("");
  }
  return lines.join("\n");
}

function table(cols: string[], rs: Row[]): string {
  if (rs.length === 0) return "_(no rows)_";
  const head = `| ${cols.join(" | ")} |`;
  const sep = `| ${cols.map(() => "---").join(" | ")} |`;
  const body = rs.map(
    (r) =>
      `| ${cols
        .map((c) => fmt(r[c]))
        .join(" | ")} |`,
  );
  return [head, sep, ...body].join("\n");
}

function fmt(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v.replace(/\|/g, "\\|").replace(/\n/g, " ");
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "object") return JSON.stringify(v).replace(/\|/g, "\\|");
  return String(v);
}
