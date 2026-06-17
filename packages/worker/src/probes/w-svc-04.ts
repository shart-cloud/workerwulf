import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wSvc04: Probe = async ({ runId }) => {
  return base({
    test_id: "W-SVC-04",
    track: "worker",
    description:
      "Service binding chain identity propagation (A→B→C) — informational, requires 3 Worker deployment",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      implemented: false,
      requires: [
        "Three Workers: wulf-worker (A), wulf-svc-relay (B), wulf-svc-chain (C)",
        "Service binding A→B, B→C configured in each wrangler.toml",
        "Each Worker logs its request.cf object and headers at each hop",
      ],
      expected_behavior:
        "cf object should propagate colo info but ray ID should change per hop",
      note: "This probe requires additional deployment infrastructure. To test: deploy 3 Workers with service binding chains, add a relay endpoint to each, then add a probe that drives the chain end-to-end.",
    },
    comparison: {
      aws_lambda: "N/A (no equivalent chaining)",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};