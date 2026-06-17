import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSq308: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQ3-08");
  await doFetch(stub, "http://do/init-schema");

  const data = await doFetch<{ pitr_api_accessible?: boolean; note?: string }>(stub, "http://do/pitr-abuse");

  return base({
    test_id: "DO-SQ3-08",
    track: "durable",
    description: "Test PITR (Point-in-Time Recovery) abuse",
    result: data.pitr_api_accessible ? "accessible" : "blocked",
    severity: data.pitr_api_accessible ? "high" : "informational",
    run_id: runId,
    details: {
      pitr_api_accessible: data.pitr_api_accessible,
      note: data.note,
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
