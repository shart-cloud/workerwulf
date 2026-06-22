import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

/**
 * P-LIM-03 — Budget amplification / escape.
 *
 * Custom limits are *per-invocation*. The WfP analog of the AI-INJ-06 fork-bomb
 * question: within a tightly-limited invocation, can a user Worker fan work *outside*
 * its budget — schedule DO alarms, enqueue Queue messages, or chain dispatches? If so
 * the operator's per-invocation cost control is bypassable even though each invocation
 * is individually compliant. Prey reports which amplification primitives are reachable.
 */
export const pLim03: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const limits = { cpuMs: 10, subRequests: 5 } satisfies DynamicDispatchLimits;

  let body: Record<string, unknown> = {};
  let threw = false;
  let error: string | null = null;
  try {
    const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "amplify", {}, { mode, limits });
    body = resp.body ?? {};
  } catch (err) {
    threw = true;
    error = err instanceof Error ? err.message : String(err);
  }

  const offBudget = Boolean(body.off_budget_work_achieved);

  return base({
    test_id: "P-LIM-03",
    track: "platform",
    description: "Per-invocation budget amplification / escape via DO alarms, Queue enqueue, or secondary dispatch",
    result: offBudget ? "accessible" : "blocked",
    severity: offBudget ? "medium" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      limits,
      alarm_scheduling_available: Boolean(body.alarm_scheduling_available),
      queue_enqueue_available: Boolean(body.queue_enqueue_available),
      secondary_dispatch_available: Boolean(body.secondary_dispatch_available),
      off_budget_work_achieved: offBudget,
      invocation_threw: threw,
      error,
      raw: body,
      note: "Whether per-invocation limits bound total tenant resource consumption, or only single-invocation consumption.",
    },
  });
};
