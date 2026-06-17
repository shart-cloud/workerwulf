import type { Probe } from "./index.js";
import { base, childData, getChildDoRpc, invokeChild, loadChild } from "./_helpers.js";

/**
 * D-DO-03 — Cross-object access from Dynamic Worker sandbox
 * (Corresponds to PRD DO-DYN-03)
 */
export const dDo03: Probe = async ({ env, ctx, runId }) => {
  if (!env.CHILD_DO) {
    return base({
      test_id: "D-DO-03",
      track: "dynamic",
      description: "Cross-object access from Dynamic Worker sandbox",
      result: "error",
      severity: "informational",
      run_id: runId,
      details: { error: "CHILD_DO binding not configured in wrangler.toml" },
    });
  }

  const stub = loadChild(env, {
    env: { CHILD_DO_RPC: getChildDoRpc(ctx) },
  });

  const { body } = await invokeChild(stub, "do-cross-object", {
    binding: "CHILD_DO_RPC",
    target_name: "D-DO-03-other",
  });

  const data = childData<{
    original_name?: string;
    guessed_name?: string;
    original_id?: string;
    guessed_id?: string;
    ids_equal?: boolean;
    marker_user?: string;
    marker_visible_from_guessed_object?: boolean;
    note?: string;
  }>(body);
  const childCanReachDifferentObject = Boolean(data?.guessed_id && data.original_id !== data.guessed_id);

  return base({
    test_id: "D-DO-03",
    track: "dynamic",
    description: "Cross-object access from Dynamic Worker sandbox",
    result: childCanReachDifferentObject ? "accessible" : "blocked",
    severity: childCanReachDifferentObject ? "medium" : "informational",
    run_id: runId,
    details: {
      child_used_do_binding: true,
      original_name: data?.original_name,
      guessed_name: data?.guessed_name,
      original_id: data?.original_id,
      guessed_id: data?.guessed_id,
      ids_equal: data?.ids_equal,
      child_can_reach_different_object: childCanReachDifferentObject,
      marker_user: data?.marker_user,
      marker_visible_from_guessed_object: data?.marker_visible_from_guessed_object,
      note: data?.note,
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
