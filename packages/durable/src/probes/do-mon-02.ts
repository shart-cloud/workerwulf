import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doMon02: Probe = async ({ env, runId }) => {
  // DO-MON-02: Test whether storage anomalies trigger alerts.
  // We rapidly create tables and insert bulk data, then check if any
  // platform-level signals are observable.
  const stub = getDoStub(env, "PREY_DO", "DO-MON-02");
  await doFetch(stub, "http://do/init-schema");

  const t0 = Date.now();
  const data = await doFetch<{
    inserted?: number;
    elapsed_ms?: number;
    limit_reached?: boolean;
    error?: string;
  }>(stub, "http://do/storage-dos?size=500");

  return base({
    test_id: "DO-MON-02",
    track: "durable",
    description:
      "Test whether storage anomalies (mass writes, schema changes) trigger alerts",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      inserted: data.inserted,
      elapsed_ms: data.elapsed_ms,
      total_elapsed_ms: Date.now() - t0,
      limit_reached: data.limit_reached,
      error: data.error,
      note: "No platform alert API is exposed to Workers; this probe documents behavior under load",
    },
    comparison: {
      aws_lambda: "CloudWatch Alarms (configurable)",
      azure_functions: "Azure Monitor Alerts",
      gcp_functions: "Cloud Monitoring Alerts",
    },
  });
};
