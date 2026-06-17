import { buildControlledHostname } from "@wulf/shared";
import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dNet02: Probe = async ({ env, runId }) => {
  if (!env.WULF_DNS_EXFIL_ZONE) {
    return base({
      test_id: "D-NET-02",
      track: "dynamic",
      description: "DNS-based exfil probe against controlled authoritative zone",
      result: "error",
      severity: "medium",
      run_id: runId,
      details: {
        error: "WULF_DNS_EXFIL_ZONE is not configured",
      },
    });
  }

  const openHost = buildControlledHostname({
    zone: env.WULF_DNS_EXFIL_ZONE,
    testId: "D-NET-02",
    runId,
    prefix: "open",
  });
  const closedHost = buildControlledHostname({
    zone: env.WULF_DNS_EXFIL_ZONE,
    testId: "D-NET-02",
    runId,
    prefix: "closed",
  });
  const openURL = `http://${openHost}/dns-exfil?track=dynamic&test_id=D-NET-02&run_id=${encodeURIComponent(runId)}`;
  const closedURL = `http://${closedHost}/dns-exfil?track=dynamic&test_id=D-NET-02&run_id=${encodeURIComponent(runId)}`;

  const openStub = loadChild(env);
  const closedStub = loadChild(env, { globalOutbound: null });

  const openResp = await invokeChild(openStub, "try-fetch", { target: openURL });
  const closedResp = await invokeChild(closedStub, "try-fetch", {
    target: closedURL,
  });

  return base({
    test_id: "D-NET-02",
    track: "dynamic",
    description: "DNS-based exfil probe against controlled authoritative zone",
    target: closedURL,
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      dns_zone: env.WULF_DNS_EXFIL_ZONE,
      open_control: {
        hostname: openHost,
        url: openURL,
        response: openResp.body,
        status: openResp.status,
        ok: openResp.ok,
      },
      closed_attempt: {
        hostname: closedHost,
        url: closedURL,
        response: closedResp.body,
        status: closedResp.status,
        ok: closedResp.ok,
      },
      requires_callback_log_verification: true,
      verification_hint:
        "Look for dns events for the closed_attempt hostname in the callback receiver logs or R2 bucket.",
    },
  });
};
