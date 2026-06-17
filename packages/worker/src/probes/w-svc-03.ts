import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const RECURSION_SIGNAL = `wulf-self-bind-${Date.now().toString(36)}`;
let maxDepthReached = 0;
let terminationReason: string | null = null;

export const wSvc03: Probe = async ({ env, req, runId }) => {
  const self = env.SVC_SELF;
  const url = new URL(req.url);
  const depth = parseInt(url.searchParams.get("depth") || "0", 10);

  const details: Record<string, unknown> = { depth };

  if (depth === 0) {
    // Entry point: start recursive chain
    try {
      const res = await self.fetch(
        new Request(`https://wulf-self.invalid/probe/W-SVC-03?run_id=${encodeURIComponent(runId)}&depth=1`),
      );
      // We'll get back a JSON from the recursive call or the chain will break
      if (res.ok) {
        const body = await res.json() as Record<string, unknown>;
        const nested = body.details as Record<string, unknown> | undefined;
        details.max_depth_reached = nested?.max_depth_reached ?? body.max_depth_reached ?? depth;
        details.termination_reason = nested?.termination_reason ?? body.termination_reason;
        details.subrequest_limit = nested?.subrequest_limit ?? body.subrequest_limit;
      } else {
        details.error_status = res.status;
        try {
          details.error_body = await res.text();
        } catch {
          // ignore
        }
      }

      // Try fetching our own probes endpoint via the self-binding too
      const probesRes = await self.fetch(
        new Request("https://wulf-self.invalid/probes"),
      );
      if (probesRes.ok) {
        const probesBody = await probesRes.json() as { probes: string[] };
        details.self_binding_works = true;
        details.probes_visible = probesBody.probes?.length ?? 0;
      }
    } catch (err) {
      details.self_call_error = err instanceof Error ? err.message : String(err);
      details.self_binding_works = false;

      // Try without recursion to check basic self-binding
      try {
        const test = await self.fetch(new Request("https://wulf-self.invalid/probes"));
        if (test.ok) {
          details.non_recursive_self_call = true;
        }
      } catch {
        details.non_recursive_self_call = false;
      }
    }
  } else {
    // Intermediate recursion: call ourselves deeper
    const nextDepth = depth + 1;
    try {
      const res = await self.fetch(
        new Request(`https://wulf-self.invalid/probe/W-SVC-03?run_id=${encodeURIComponent(runId)}&depth=${nextDepth}`),
      );
      if (res.ok) {
        const body = await res.json() as Record<string, unknown>;
        const nested = body.details as Record<string, unknown> | undefined;
        return base({
          test_id: "W-SVC-03",
          track: "worker",
          description: "Recursive self-binding — intermediate depth",
          result: "informational",
          severity: "informational",
          run_id: runId,
          details: {
            depth,
            max_depth_reached: nested?.max_depth_reached ?? depth,
            termination_reason: nested?.termination_reason,
            subrequest_limit: nested?.subrequest_limit,
          },
        } as Parameters<typeof base>[0]);
      }
    } catch (err) {
      terminationReason = err instanceof Error ? err.message : String(err);
      // Can't propagate — this is the termination point
    }
  }

  maxDepthReached = Math.max(maxDepthReached, depth);

  return base({
    test_id: "W-SVC-03",
    track: "worker",
    description: "Recursive self-binding — what happens when a Worker calls itself via service binding",
    result: "informational",
    severity: depth > 10 ? "medium" : "informational",
    run_id: runId,
    details: {
      depth,
      max_depth_reached: Math.max(maxDepthReached, depth),
      termination_reason: terminationReason ?? null,
      subrequest_limit: terminationReason?.includes("subrequest") ? "enforced" : null,
    },
    comparison: {
      aws_lambda: "N/A (no service binding recursion)",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
