import type { Probe } from "./index.js";
import { base, callbackTarget, checkCallback, invokeTenant, namespaceMode, outboundLogKeys } from "./_helpers.js";

export const pOut03: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const since = new Date().toISOString();
  const resolved = callbackTarget(c, "P-OUT-03", "/evade-b64-url");
  const b64 = btoa(resolved);
  const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "residual-b64", { b64 }, { mode });
  const callback = await checkCallback(c, "P-OUT-03", since);
  const logKeys = await outboundLogKeys(c.env, "P-OUT-03", c.runId);
  const callbackReceived = Boolean(callback.found);
  const egressBlocked = !Boolean(resp.body.reachable) && !callbackReceived;

  return base({
    test_id: "P-OUT-03",
    track: "platform",
    description: "Replay Track 4 evade-b64-url residual against WfP outbound allowlist",
    result: egressBlocked ? "blocked" : "accessible",
    severity: egressBlocked ? "informational" : "high",
    run_id: c.runId,
    details: {
      namespace: mode,
      payload: "evade-b64-url",
      source_obfuscation: "base64_atob_fetch",
      static_analysis_would_catch: false,
      outbound_allowlist_active: true,
      resolved_fetch_host: new URL(resolved).host,
      egress_blocked_by_outbound: egressBlocked,
      callback_received: callbackReceived,
      user_worker_fetch: resp.body,
      outbound_log_keys: logKeys,
      callback_check: callback,
    },
  });
};
