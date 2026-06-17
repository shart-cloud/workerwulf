import type { Probe } from "./index.js";
import { base, childData, getChildDoRpc, invokeChild, loadChild } from "./_helpers.js";

/**
 * D-DO-04 — WebSocket hibernation API abuse from Dynamic Worker sandbox
 * (Corresponds to PRD DO-DYN-04)
 */
export const dDo04: Probe = async ({ env, ctx, runId }) => {
  if (!env.CHILD_DO) {
    return base({
      test_id: "D-DO-04",
      track: "dynamic",
      description: "WebSocket hibernation API abuse from Dynamic Worker sandbox",
      result: "error",
      severity: "informational",
      run_id: runId,
      details: { error: "CHILD_DO binding not configured in wrangler.toml" },
    });
  }

  const stub = loadChild(env, {
    env: { CHILD_DO_RPC: getChildDoRpc(ctx) },
  });

  const { body } = await invokeChild(stub, "do-websocket-hibernate", {
    binding: "CHILD_DO_RPC",
  });

  const data = childData<{
    websocket_upgrade_supported?: boolean | null;
    hibernation_api_callable?: boolean;
    note?: string;
  }>(body);

  return base({
    test_id: "D-DO-04",
    track: "dynamic",
    description: "WebSocket hibernation API abuse from Dynamic Worker sandbox",
    result: data?.hibernation_api_callable ? "accessible" : "blocked",
    severity: data?.hibernation_api_callable ? "medium" : "informational",
    run_id: runId,
    details: {
      child_used_do_binding: true,
      websocket_upgrade_supported: data?.websocket_upgrade_supported,
      hibernation_api_callable: data?.hibernation_api_callable,
      note: data?.note,
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
