import type { Probe } from "./index.js";
import { base, delegatedResult, fetchDynamicProbe } from "./_helpers.js";

export const doDyn04: Probe = async ({ env, runId }) => {
  const dynamic = await fetchDynamicProbe({
    baseUrl: env.WULF_DYNAMIC_BASE_URL,
    fetcher: env.DYNAMIC_PARENT,
    testId: "D-DO-04",
    runId,
  });
  if (dynamic) {
    return delegatedResult({
      dynamic,
      testId: "DO-DYN-04",
      description: "Abuse DO WebSocket hibernation API from untrusted code",
      runId,
    });
  }

  // DO-DYN-04: Abuse DO WebSocket hibernation API from untrusted code.
  // This probe attempts to create a WebSocket pair via the DO and test
  // hibernation state manipulation.
  const hibernationApi: string[] = [];

  return base({
    test_id: "DO-DYN-04",
    track: "durable",
    description: "Abuse DO WebSocket hibernation API from untrusted code",
    result: "partial",
    severity: "informational",
    run_id: runId,
    details: {
      websocket_supported: null,
      hibernation_api: hibernationApi,
      note: "Not executed in this package. Configure WULF_DYNAMIC_BASE_URL to delegate to packages/dynamic-parent D-DO-04.",
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
