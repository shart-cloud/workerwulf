import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

export const pOut05: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const body = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "response-exfil", { channel: "body" }, { mode });
  const error = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "response-exfil", { channel: "error" }, { mode });
  const t0 = Date.now();
  const timing = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "response-exfil", { channel: "timing" }, { mode });
  const timingMs = Date.now() - t0;

  const bodyExfil = JSON.stringify(body.body).includes("CANARY") || JSON.stringify(body.body).includes("flag{");
  const errorExfil = JSON.stringify(error.body).includes("CANARY") || JSON.stringify(error.body).includes("flag{");
  const timingExfil = timingMs > 25 && timing.ok;

  return base({
    test_id: "P-OUT-05",
    track: "platform",
    description: "Exfiltration through response, error, and timing channels not mediated by outbound Worker",
    result: bodyExfil || errorExfil || timingExfil ? "accessible" : "blocked",
    severity: "medium",
    run_id: c.runId,
    details: {
      namespace: mode,
      channels: {
        response_body: { exfil_possible: bodyExfil, status: body.status, body: body.body },
        error_message_relay: { exfil_possible: errorExfil, status: error.status, body: error.body },
        timing: { exfil_possible: timingExfil, elapsed_ms: timingMs, body: timing.body },
      },
      note: "Outbound Workers mediate user fetch(), not response bodies, error bodies, or timing returned through the dispatch path.",
    },
  });
};
