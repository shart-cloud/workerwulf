import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

export const pLim01: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const limits = { cpuMs: 10, subRequests: 5 } satisfies DynamicDispatchLimits;
  const cpu = await captureLimitedInvocation(c, "cpu-burn", { ms: "250" }, limits, mode);
  const subrequests = await captureLimitedInvocation(
    c,
    "subrequest-fanout",
    { target: c.env.WULF_ALLOWED_TEST_URL ?? "https://cloudflare.com/cdn-cgi/trace", count: "10" },
    limits,
    mode,
  );
  const cpuLimitEnforced = cpu.threw || !cpu.ok;
  const subrequestLimitEnforced = subrequests.threw || !subrequests.ok;

  return base({
    test_id: "P-LIM-01",
    track: "platform",
    description: "Custom-limit enforcement baseline for WfP user Worker invocations",
    result: cpuLimitEnforced && subrequestLimitEnforced ? "blocked" : cpuLimitEnforced || subrequestLimitEnforced ? "partial" : "accessible",
    severity: cpuLimitEnforced && subrequestLimitEnforced ? "informational" : "medium",
    run_id: c.runId,
    details: {
      namespace: mode,
      cpu_limit_ms: limits.cpuMs,
      cpu_limit_enforced: cpuLimitEnforced,
      subrequest_limit: limits.subRequests,
      subrequest_limit_enforced: subrequestLimitEnforced,
      exception_surfaced_to_dispatch: cpu.threw || subrequests.threw,
      cpu,
      subrequests,
    },
  });
};

async function captureLimitedInvocation(
  c: Parameters<Probe>[0],
  cmd: string,
  params: Record<string, string>,
  limits: DynamicDispatchLimits,
  mode: "trusted" | "untrusted",
): Promise<Record<string, unknown> & { ok: boolean; threw: boolean }> {
  try {
    const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", cmd, params, { mode, limits });
    return { ok: resp.ok, threw: false, status: resp.status, body: resp.body };
  } catch (err) {
    return { ok: false, threw: true, error: err instanceof Error ? err.message : String(err) };
  }
}
