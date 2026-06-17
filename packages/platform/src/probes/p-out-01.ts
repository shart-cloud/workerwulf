import type { Probe } from "./index.js";
import { base, callbackTarget, checkCallback, invokeTenant, namespaceMode, outboundLogKeys } from "./_helpers.js";

export const pOut01: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const since = new Date().toISOString();
  const allowlistedTarget = c.env.WULF_ALLOWED_TEST_URL ?? "https://cloudflare.com/cdn-cgi/trace";
  const blockedTarget = callbackTarget(c, "P-OUT-01");

  const allowlisted = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "try-fetch", { target: allowlistedTarget }, { mode });
  const blocked = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "try-fetch", { target: blockedTarget }, { mode });
  const callback = await checkCallback(c, "P-OUT-01", since);
  const logKeys = await outboundLogKeys(c.env, "P-OUT-01", c.runId);

  const allowlistedReachable = Boolean(allowlisted.body.reachable);
  const blockedReachable = Boolean(blocked.body.reachable);
  const callbackReceived = Boolean(callback.found);
  const enforcementCorrect = allowlistedReachable && !blockedReachable && !callbackReceived;

  return base({
    test_id: "P-OUT-01",
    track: "platform",
    description: "Outbound Worker interception baseline for allowlisted and blocked user-Worker fetch()",
    result: enforcementCorrect ? "blocked" : "accessible",
    severity: enforcementCorrect ? "informational" : "high",
    run_id: c.runId,
    details: {
      namespace: mode,
      allowlisted_fetch: { target: allowlistedTarget, intercepted: logKeys.length > 0, ...allowlisted.body },
      blocked_fetch: { target: blockedTarget, intercepted: logKeys.length > 0, callback_received: callbackReceived, ...blocked.body },
      outbound_log_keys: logKeys,
      callback_check: callback,
      enforcement_correct: enforcementCorrect,
    },
  });
};
