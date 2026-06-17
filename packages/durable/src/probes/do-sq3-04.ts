import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSq304: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQ3-04");
  await doFetch(stub, "http://do/init-schema");

  const data = await doFetch<{ rows?: unknown[] }>(stub, "http://do/sqlite-master");
  const rows = data.rows ?? [];

  return base({
    test_id: "DO-SQ3-04",
    track: "durable",
    description: "Enumerate sqlite_master for full schema discovery",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
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
