import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dEnv06: Probe = async ({ env, runId }) => {
  // Empty env explicitly forwarded — but child still might see something
  // injected by the runtime (Symbols, accessors, prototype methods).
  const stub = loadChild(env, { env: {} });
  const { body } = await invokeChild(stub, "deep-env-walk");
  const data = (body as { ok: boolean; data: Record<string, unknown> }).data;

  const hiddenCount = Array.isArray(data["hidden_from_enumerable"])
    ? (data["hidden_from_enumerable"] as string[]).length
    : 0;
  const symbolCount = Array.isArray(data["own_symbols"])
    ? (data["own_symbols"] as string[]).length
    : 0;

  return base({
    test_id: "D-ENV-06",
    track: "dynamic",
    description: "Deep env walk inside the child — accessors, symbols, proto chain",
    result: "informational",
    severity:
      hiddenCount > 0 || symbolCount > 0 ? "low" : "informational",
    run_id: runId,
    details: data,
  });
};
