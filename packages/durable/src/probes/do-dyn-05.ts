import type { Probe } from "./index.js";
import { base, delegatedResult, fetchDynamicProbe } from "./_helpers.js";

export const doDyn05: Probe = async ({ env, runId }) => {
  const dynamic = await fetchDynamicProbe({
    baseUrl: env.WULF_DYNAMIC_BASE_URL,
    fetcher: env.DYNAMIC_PARENT,
    testId: "D-DO-05",
    runId,
  });
  if (dynamic) {
    return delegatedResult({
      dynamic,
      testId: "DO-DYN-05",
      description: "Alarm API abuse from Dynamic Worker sandbox",
      runId,
    });
  }

  // DO-DYN-05: Test alarm API abuse — can a Dynamic Worker schedule
  // persistent alarms? We test from the parent Worker perspective by
  // attempting to set an alarm on the DO.

  return base({
    test_id: "DO-DYN-05",
    track: "durable",
    description: "Alarm API abuse from Dynamic Worker sandbox",
    result: "partial",
    severity: "informational",
    run_id: runId,
    details: {
      alarm_accessible: null,
      note: "Not executed in this package. Configure WULF_DYNAMIC_BASE_URL to delegate to packages/dynamic-parent D-DO-05.",
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
