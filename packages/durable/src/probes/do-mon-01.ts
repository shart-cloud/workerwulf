import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const doMon01: Probe = async ({ runId }) => {
  return base({
    test_id: "DO-MON-01",
    track: "durable",
    description: "Determine what SQL activity is visible in Tail Workers",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      status: "blocked",
      reason: "Tail Worker (prey-tail) not yet implemented",
      note: "Deploy a Tail Worker alongside the DO, then re-run this probe",
    },
    comparison: {
      aws_lambda: "CloudTrail / VPC Flow Logs",
      azure_functions: "Diagnostic Logs",
      gcp_functions: "Cloud Audit Logs",
    },
  });
};
