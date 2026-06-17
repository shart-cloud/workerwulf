import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dCap03: Probe = async ({ env, runId }) => {
  const stub = loadChild(env, { env: {} });
  const { body } = await invokeChild(stub, "probe-parent");

  const data = (body as { ok: boolean; data: Record<string, unknown> }).data;

  // Heuristic: if any reflection trick surfaces strings like "PARENT_" or
  // the secret decoy substring, treat as a leak.
  const serialized = JSON.stringify(data);
  const decoyLeaked = serialized.includes("if-you-can-read-this-from-child");
  const parentRefLeaked = /PARENT_(KV|R2|D1|SECRET)/.test(serialized);

  const leaked = decoyLeaked || parentRefLeaked;

  return base({
    test_id: "D-CAP-03",
    track: "dynamic",
    description: "Reflection-based probing for parent env/secret leakage",
    result: leaked ? "accessible" : "blocked",
    severity: leaked ? "critical" : "informational",
    run_id: runId,
    details: {
      decoy_string_found: decoyLeaked,
      parent_binding_name_found: parentRefLeaked,
      reflection_findings: data,
    },
  });
};
