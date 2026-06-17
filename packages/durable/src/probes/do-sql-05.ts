import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSql05: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQL-05");
  await doFetch(stub, "http://do/init-schema");

  // Error-based: intentionally reference a missing table through injected SQL.
  const payload = "1 UNION SELECT * FROM definitely_missing_table";
  const data = await doFetch<{ error?: string | null; rows?: unknown[] }>(
    stub,
    `http://do/error-based?input=${encodeURIComponent(payload)}`,
  );

  const errorMsg = data.error;
  const leakedSchema =
    errorMsg &&
    (errorMsg.toLowerCase().includes("table") ||
      errorMsg.toLowerCase().includes("column") ||
      errorMsg.toLowerCase().includes("no such"));

  return base({
    test_id: "DO-SQL-05",
    track: "durable",
    description: "Error-based injection for schema disclosure",
    result: leakedSchema ? "accessible" : "blocked",
    severity: leakedSchema ? "medium" : "informational",
    run_id: runId,
    details: {
      payload,
      error: errorMsg,
      leaked_schema: leakedSchema,
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
