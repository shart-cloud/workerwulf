import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-CAP-08 — Workers Analytics Engine capability-binding blast radius (misconfig).
 *
 * An Analytics Engine binding is write-anything telemetry: `env.AE.writeDataPoint()`
 * accepts arbitrary blobs/indexes/doubles with no schema and no authz. A
 * compromised Worker can **poison the very telemetry defenders rely on** — flood
 * the dataset to bury real signal (detection blinding), or forge data points to
 * fabricate or drown out evidence. This is the dataset DO-MON-03 maps as the
 * SQL-operation detection channel, so the binding undermines integrity of the
 * detection layer itself, not confidentiality. This probe writes one run-tagged
 * canary data point and reports that the write was accepted.
 *
 * Deploy-only: requires the live AE binding + a dataset. Locally → blocked.
 */
export const wCap08: Probe = async ({ env, runId }) => {
  const ae = env.AE;
  if (!ae) {
    return base({
      test_id: "W-CAP-08",
      track: "worker",
      description:
        "Analytics Engine capability binding — write forged/poison data points into the detection telemetry via env.AE.writeDataPoint()",
      target: "env.AE",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: { error: "AE binding not present (expected locally / pre-deploy)" },
    });
  }

  let wrote = false;
  let error: string | null = null;
  const dataPoint = {
    indexes: [`wulf-cap-08-${runId.slice(0, 8)}`],
    blobs: ["flag{w-cap-08-analytics-canary}", "forged telemetry — no schema/authz on writeDataPoint", runId],
    doubles: [1],
  };

  try {
    // writeDataPoint is fire-and-forget (returns void); a throw is the only
    // negative signal. Single point only — poisoning is proven, not performed.
    ae.writeDataPoint(dataPoint);
    wrote = true;
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return base({
    test_id: "W-CAP-08",
    track: "worker",
    description:
      "Analytics Engine capability binding — write forged/poison data points into the detection telemetry via env.AE.writeDataPoint()",
    target: "env.AE",
    result: wrote ? "accessible" : error ? "error" : "partial",
    severity: wrote ? "medium" : "low",
    run_id: runId,
    tags: ["misconfig", "misconfig:binding"],
    details: {
      data_point_written: wrote,
      data_point: dataPoint,
      error,
      note: "An Analytics Engine binding accepts unauthenticated, unschematized writes from any code in the isolate. The same dataset defenders query for SQL-op detection (DO-MON-03) can be flooded to bury signal or forged to fabricate evidence — a detection-integrity, not confidentiality, blast radius. writeDataPoint returns void, so acceptance is the verdict.",
    },
    comparison: {
      aws_lambda:
        "accessible — analog to cloudwatch:PutMetricData / firehose:PutRecord granted to the function role, polluting the metrics/log pipeline",
      azure_functions: "accessible — Application Insights ingestion key usable to forge custom events",
      gcp_functions: "accessible — monitoring.timeSeries.create / logging write on the runtime SA",
    },
  });
};
