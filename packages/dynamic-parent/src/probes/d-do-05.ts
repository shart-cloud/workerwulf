import type { Probe } from "./index.js";
import { base, childData, getChildDoRpc, invokeChild, loadChild } from "./_helpers.js";

/**
 * D-DO-05 — Alarm API abuse from Dynamic Worker sandbox
 * (Corresponds to PRD DO-DYN-05)
 */
export const dDo05: Probe = async ({ env, ctx, runId }) => {
  if (!env.CHILD_DO) {
    return base({
      test_id: "D-DO-05",
      track: "dynamic",
      description: "Alarm API abuse from Dynamic Worker sandbox",
      result: "error",
      severity: "informational",
      run_id: runId,
      details: { error: "CHILD_DO binding not configured in wrangler.toml" },
    });
  }

  const stub = loadChild(env, {
    env: { CHILD_DO_RPC: getChildDoRpc(ctx) },
  });

  const { body } = await invokeChild(stub, "do-alarm-schedule", {
    binding: "CHILD_DO_RPC",
  });

  const data = childData<{ alarm_api_callable?: boolean; error?: string | null; note?: string }>(body);

  return base({
    test_id: "D-DO-05",
    track: "dynamic",
    description: "Alarm API abuse from Dynamic Worker sandbox",
    result: data?.alarm_api_callable ? "accessible" : "blocked",
    severity: data?.alarm_api_callable ? "medium" : "informational",
    run_id: runId,
    details: {
      child_used_do_binding: true,
      alarm_api_callable: data?.alarm_api_callable,
      error: data?.error,
      note: data?.note,
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
