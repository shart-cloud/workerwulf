import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSq307: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQ3-07");
  await doFetch(stub, "http://do/init-schema");

  // Attempt to insert 1000 rows of 1KB each = ~1MB
  const data = await doFetch<{
    inserted?: number;
    elapsed_ms?: number;
    limit_reached?: boolean;
    error?: string;
  }>(stub, "http://do/storage-dos?size=1000");

  return base({
    test_id: "DO-SQ3-07",
    track: "durable",
    description: "Probe storage limits for denial-of-service potential",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      inserted: data.inserted,
      elapsed_ms: data.elapsed_ms,
      limit_reached: data.limit_reached,
      error: data.error,
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
