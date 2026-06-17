import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSql01: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQL-01");
  await doFetch(stub, "http://do/init-schema");

  const payload = "admin' OR '1'='1";
  const data = await doFetch<{ rows?: unknown[]; query?: string }>(
    stub,
    `http://do/classic-sqli?input=${encodeURIComponent(payload)}`,
  );

  const rows = data.rows ?? [];
  const leaked = rows.length > 1; // should return all users if injectable

  return base({
    test_id: "DO-SQL-01",
    track: "durable",
    description: "Classic SQLi via string concatenation in sql.exec",
    result: leaked ? "accessible" : "blocked",
    severity: leaked ? "critical" : "informational",
    run_id: runId,
    details: {
      payload,
      row_count: rows.length,
      query: data.query,
      rows,
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
