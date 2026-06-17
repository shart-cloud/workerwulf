import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dCap02: Probe = async ({ env, runId }) => {
  // Load child with explicitly empty env. Parent has PARENT_KV, PARENT_R2,
  // PARENT_D1, PARENT_SECRET_DECOY — none should be visible to the child.
  const stub = loadChild(env, { env: {} });
  const { body } = await invokeChild(stub, "enumerate-env");

  type EnvData = {
    count: number;
    entries: Array<{ name: string }>;
    env_is_null: boolean;
  };
  const data = (body as { ok: boolean; data: EnvData }).data;

  const parentBindings = ["PARENT_KV", "PARENT_R2", "PARENT_D1", "PARENT_SECRET_DECOY"];
  const childKeys = data.entries.map((e) => e.name);
  const leaked = parentBindings.filter((n) => childKeys.includes(n));

  return base({
    test_id: "D-CAP-02",
    track: "dynamic",
    description: "Child cannot see parent bindings unless explicitly forwarded",
    result: leaked.length === 0 ? "blocked" : "accessible",
    severity: leaked.length === 0 ? "informational" : "critical",
    run_id: runId,
    details: {
      child_env_count: data.count,
      child_env_keys: childKeys,
      parent_bindings_probed: parentBindings,
      leaked,
    },
  });
};
