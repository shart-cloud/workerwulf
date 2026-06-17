import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSq303: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQ3-03");
  await doFetch(stub, "http://do/init-schema");

  const data = await doFetch<{ exists?: boolean; rows?: unknown[]; error?: string }>(stub, "http://do/cf-kv-table");

  return base({
    test_id: "DO-SQ3-03",
    track: "durable",
    description: "Access the hidden __cf_kv table via SQL",
    result: data.exists ? "accessible" : "blocked",
    severity: data.exists ? "high" : "informational",
    run_id: runId,
    details: {
      exists: data.exists,
      rows: data.rows,
      error: data.error,
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
