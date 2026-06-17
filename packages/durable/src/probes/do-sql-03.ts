import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSql03: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQL-03");
  await doFetch(stub, "http://do/init-schema");

  // UNION injection to extract cross-table data
  const payload =
    "admin' UNION SELECT id, password FROM users --";
  const data = await doFetch<{ rows?: unknown[]; query?: string }>(
    stub,
    `http://do/union-inject?input=${encodeURIComponent(payload)}`,
  );
  const rows = data.rows ?? [];

  // Check if passwords were extracted via UNION
  const leakedPasswords = rows.some(
    (r: unknown) =>
      r &&
      typeof r === "object" &&
      typeof (r as Record<string, unknown>).username === "string" &&
      (r as Record<string, unknown>).username !== "admin" &&
      (r as Record<string, unknown>).username !== "guest",
  );

  return base({
    test_id: "DO-SQL-03",
    track: "durable",
    description: "UNION-based injection for cross-table data extraction",
    result: leakedPasswords ? "accessible" : "blocked",
    severity: leakedPasswords ? "critical" : "informational",
    run_id: runId,
    details: {
      payload,
      row_count: rows.length,
      rows,
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
