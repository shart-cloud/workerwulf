import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

export const pDisp01: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "env-enum", {}, { mode });
  const dispatcherKeys = (resp.body.dispatcher_keys as string[] | undefined) ?? [];
  const dispatcherPresent = dispatcherKeys.length > 0;

  return base({
    test_id: "P-DISP-01",
    track: "platform",
    description: "Dispatch binding reachability from a Workers for Platforms user Worker",
    result: dispatcherPresent ? "accessible" : "blocked",
    severity: dispatcherPresent ? "critical" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      user_worker_status: resp.status,
      user_worker_env_keys: resp.body.env_keys ?? [],
      dispatcher_binding_present: dispatcherPresent,
      dispatcher_get_callable: dispatcherPresent,
      dispatcher_keys: dispatcherKeys,
      raw: resp.body,
    },
  });
};
