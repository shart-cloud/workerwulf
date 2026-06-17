import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dNet03: Probe = async ({ env, req, runId }) => {
  const url = new URL(req.url);
  const sizeParam = url.searchParams.get("size") ?? "65536";

  // Even with globalOutbound:null, the RPC return path is still a channel
  // back to the parent. If untrusted code inside the sandbox has access to
  // any data worth stealing, it can exfiltrate via the response payload.
  const stub = loadChild(env, { globalOutbound: null });
  const t0 = Date.now();
  const { body } = await invokeChild(stub, "rpc-exfil", {
    "payload-size": sizeParam,
  });
  const dt = Date.now() - t0;

  type Data = { requested_size: number; actual_size: number; payload: string };
  const data = (body as { ok: boolean; data: Data }).data;

  const transmitted = data.actual_size;
  const containsPattern = data.payload.includes("EXFIL:");

  return base({
    test_id: "D-NET-03",
    track: "dynamic",
    description:
      "Exfiltration via RPC return value (bypasses globalOutbound:null)",
    result: containsPattern && transmitted > 0 ? "accessible" : "blocked",
    severity: containsPattern && transmitted > 0 ? "medium" : "informational",
    run_id: runId,
    details: {
      requested_size_bytes: data.requested_size,
      transmitted_size_bytes: transmitted,
      latency_ms: dt,
      pattern_intact: containsPattern,
      preview_first_64: data.payload.slice(0, 64),
    },
  });
};
