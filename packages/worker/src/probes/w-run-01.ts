import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

let invocationCount = 0;
let lastRequestId = "none";

export const wRun01: Probe = async ({ req, runId }) => {
  const currentReqId = req.headers.get("cf-ray") ?? runId;
  const prev = invocationCount;
  const prevReqId = lastRequestId;

  invocationCount++;
  lastRequestId = currentReqId;

  const seqValue = new URL(req.url).searchParams.get("seq");
  const seq = seqValue ? parseInt(seqValue, 10) : 0;
  const isFirst = seq === 0;
  const isLast = !seqValue || parseInt(seqValue, 10) >= 49; // last of 50 or single run

  return base({
    test_id: "W-RUN-01",
    track: "worker",
    description:
      "Module-scope counter persistence across invocations — verify state survives across HTTP requests to the same isolate",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      seq,
      prev_counter: prev,
      current_counter: invocationCount,
      counter_persisted: prev > 0,
      prev_request_id: prevReqId,
      current_request_id: currentReqId,
      first_invocation: isFirst,
      last_invocation: isLast,
      note: isLast
        ? `Counter reached ${invocationCount} across sequential invocations — module-scope state persists`
        : undefined,
    },
    comparison: {
      aws_lambda: "informational (cold-starts reset, warm-starts persist)",
      azure_functions: "informational (depends on instance reuse)",
      gcp_functions: "informational (depends on instance reuse)",
    },
  });
};
