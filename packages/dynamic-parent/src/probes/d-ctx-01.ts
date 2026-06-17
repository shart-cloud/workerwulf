import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dCtx01: Probe = async ({ env, runId }) => {
  const stub = loadChild(env, { env: {} });
  const { body } = await invokeChild(stub, "ctx-shape");
  const data = (body as { ok: boolean; data: Record<string, unknown> }).data;

  return base({
    test_id: "D-CTX-01",
    track: "dynamic",
    description: "ExecutionContext shape from inside the Dynamic Worker isolate",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: data,
  });
};
