import type { Probe } from "./index.js";
import { base, childData, getChildDoRpc, invokeChild, loadChild } from "./_helpers.js";

/**
 * D-DO-02 — Dynamic Worker enumerating DO stub RPC surface from sandbox
 * (Corresponds to PRD DO-DYN-02)
 */
export const dDo02: Probe = async ({ env, ctx, runId }) => {
  if (!env.CHILD_DO) {
    return base({
      test_id: "D-DO-02",
      track: "dynamic",
      description: "DO stub enumeration from inside Dynamic Worker sandbox",
      result: "error",
      severity: "informational",
      run_id: runId,
      details: { error: "CHILD_DO binding not configured in wrangler.toml" },
    });
  }

  const stub = loadChild(env, {
    env: { CHILD_DO_RPC: getChildDoRpc(ctx) },
  });

  const { body } = await invokeChild(stub, "do-stub-enum", {
    binding: "CHILD_DO_RPC",
  });

  const data = childData<{ stub_methods?: string[]; stub_constructor?: string }>(body);
  const methods = data?.stub_methods ?? [];

  return base({
    test_id: "D-DO-02",
    track: "dynamic",
    description: "DO stub enumeration from inside Dynamic Worker sandbox",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      child_used_do_binding: true,
      stub_constructor: data?.stub_constructor,
      stub_methods: methods,
      method_count: methods.length,
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
