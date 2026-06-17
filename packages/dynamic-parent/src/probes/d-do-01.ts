import type { Probe } from "./index.js";
import { base, childData, getChildDoRpc, invokeChild, loadChild } from "./_helpers.js";

/**
 * D-DO-01 — Dynamic Worker with DO binding executing raw SQL
 * (Corresponds to PRD DO-DYN-01)
 */
export const dDo01: Probe = async ({ env, ctx, runId }) => {
  if (!env.CHILD_DO) {
    return base({
      test_id: "D-DO-01",
      track: "dynamic",
      description: "Dynamic Worker with DO binding executing raw SQL",
      result: "error",
      severity: "informational",
      run_id: runId,
      details: { error: "CHILD_DO binding not configured in wrangler.toml" },
    });
  }

  // Spawn a child with an RPC facade for the DO namespace. Raw DO namespaces
  // are not structured-clonable into WorkerCode.env.
  const childDoRpc = getChildDoRpc(ctx);
  const stub = loadChild(env, {
    env: { CHILD_DO_RPC: childDoRpc },
  });

  // Initialize the DO schema from inside the child
  await invokeChild(stub, "do-exec-sql", {
    name: "D-DO-01",
    op: "init-schema",
  });

  // Attempt SQL injection from inside the Dynamic Worker sandbox
  const { body } = await invokeChild(stub, "do-exec-sql", {
    name: "D-DO-01",
    op: "classic-sqli",
    input: "admin' OR '1'='1",
  });

  const data = childData<{ body?: { data?: { rows?: unknown[] } } }>(body);
  const rows = data.body?.data?.rows ?? [];
  const leaked = rows.length > 1;

  return base({
    test_id: "D-DO-01",
    track: "dynamic",
    description: "Dynamic Worker with DO binding executing raw SQL",
    result: leaked ? "accessible" : "blocked",
    severity: leaked ? "critical" : "informational",
    run_id: runId,
    details: {
      child_used_do_binding: true,
      injected_payload: "admin' OR '1'='1",
      row_count: rows.length,
      rows,
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
