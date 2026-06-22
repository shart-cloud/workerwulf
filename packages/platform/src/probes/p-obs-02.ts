import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode, outboundLogEvents } from "./_helpers.js";

const TEST_ID = "P-OBS-02";

/**
 * P-OBS-02 — Trace evasion.
 *
 * Tests whether a user Worker can perform sensitive actions invisibly to operator
 * observability: read a canary and exfil it via the response body (the P-OUT-05
 * channel) while throwing nothing, logging nothing, and making no outbound fetch.
 * Confirms whether the wulf-outbound R2 log — the only operator-queryable trace —
 * recorded anything attributable for this run.
 */
export const pObs02: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "response-exfil", { channel: "body" }, { mode });
  const bodyStr = JSON.stringify(resp.body ?? {});
  const silentExfil = bodyStr.includes("flag{") || bodyStr.includes("CANARY");

  const traceEvents = await outboundLogEvents(c.env, TEST_ID, c.runId);
  const traceRecorded = traceEvents.length > 0;
  const invisible = silentExfil && !traceRecorded;

  return base({
    test_id: TEST_ID,
    track: "platform",
    description: "Trace evasion: response-path exfil invisible to trace-based detection",
    result: invisible ? "accessible" : "blocked",
    severity: invisible ? "medium" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      silent_exfil_performed: silentExfil,
      trace_recorded_anything: traceRecorded,
      outbound_log_event_count: traceEvents.length,
      exfil_channel: "response_body",
      canary: (resp.body as { canary?: unknown } | undefined)?.canary ?? null,
      note: "Response-path exfil with no error/log/egress is invisible to the only operator observability (wulf-outbound R2 log) — reinforces P-OUT-05's response-sanitization recommendation.",
    },
  });
};
