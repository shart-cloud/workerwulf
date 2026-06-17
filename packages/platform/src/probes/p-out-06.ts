import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode, outboundLogKeys } from "./_helpers.js";

export const pOut06: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "egress-primitives", {}, { mode });
  const logKeys = await outboundLogKeys(c.env, "P-OUT-06", c.runId);
  const websocket = (resp.body.websocket as Record<string, unknown> | undefined) ?? {};
  const tcpConnect = (resp.body.tcp_connect as Record<string, unknown> | undefined) ?? {};
  const websocketConstructed = websocket.constructed === true;
  const tcpConnected = tcpConnect.connected === true;
  const unmediatedPrimitiveAvailable = (websocketConstructed || tcpConnected) && logKeys.length === 0;

  return base({
    test_id: "P-OUT-06",
    track: "platform",
    description: "Egress coverage gaps beyond user Worker fetch()",
    result: unmediatedPrimitiveAvailable ? "accessible" : "blocked",
    severity: unmediatedPrimitiveAvailable ? "high" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      websocket: { ...websocket, intercepted_by_outbound: logKeys.length > 0 },
      tcp_connect: { ...tcpConnect, intercepted_by_outbound: logKeys.length > 0 },
      dns_side_channel: resp.body.dns_side_channel,
      outbound_log_keys: logKeys,
      note: "Documents whether non-fetch egress primitives are available outside outbound Worker mediation.",
    },
  });
};
