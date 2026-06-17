import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const captured: string[] = [];

// Module-scope closure that retains mutable state across invocations
function leak() {
  return [...captured];
}

export const wRun04: Probe = async ({ req, runId }) => {
  const cfRay = req.headers.get("cf-ray") ?? `local-${runId.slice(0, 8)}`;
  captured.push(cfRay);

  const seqValue = new URL(req.url).searchParams.get("seq");
  const seq = seqValue ? parseInt(seqValue, 10) : 0;
  const isLast = !seqValue || seq >= 2;

  const leaked = leak();

  return base({
    test_id: "W-RUN-04",
    track: "worker",
    description:
      "Module-scope closure retention — closures at module scope accumulate cross-request state",
    result: "informational",
    severity: leaked.length > 1 ? "medium" : "informational",
    run_id: runId,
    details: {
      seq,
      closure_size: captured.length,
      closure_retains_across_invocations: captured.length > 1,
      previous_ray_ids_visible: captured.length > 1,
      ray_ids_accumulated: leaked.slice(-10),
      total_accumulated: captured.length,
      note: captured.length > 1
        ? `Closure retains ${captured.length} entries across invocations — previous cf-ray IDs are accessible from module-scope closure`
        : "Need multiple sequential requests to observe accumulation",
    },
    comparison: {
      aws_lambda: "accessible (module scope persists in warm container)",
      azure_functions: "accessible (module scope persists in warm instance)",
      gcp_functions: "accessible (module scope persists in warm instance)",
    },
  });
};
