import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, ctrBlocked, ctrClient, ctrCall, field } from "./_ctr.js";

const DESCR =
  "Unbounded exec output buffered into the isolate — output() as a container-driven memory-pressure channel";
const TARGET = "ExecProcess.output() / isolate memory";
const TAGS = ["container", "container:exec", "dos", "resource"];

/** Bounded ramp. Stops at the first failure — this is a boundary probe, not a flood. */
const STEPS_BYTES = [1_000_000, 8_000_000, 32_000_000, 96_000_000, 192_000_000];

/**
 * W-CTR-08 — the convenience method that crosses a resource boundary.
 *
 * `output()` buffers **both** streams into ArrayBuffers and hands them to the isolate.
 * The container's memory is governed by its instance type; the isolate's is governed by
 * the Workers memory limit. `output()` is the seam: how much a process writes to stdout
 * is decided on the container side, and the cost lands on the isolate side.
 *
 * This matters more here than in a normal OOM finding because of the recorded
 * isolate shared-fate result (co-located isolates share memory fate): an isolate
 * killed by a container's stdout is not necessarily only the attacker's isolate.
 *
 * The ramp is bounded and stops at the first failure. A failure is the *result*, not a
 * side effect to be repeated — one pass, no concurrency, no repetition.
 */
export const wCtr08: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-08",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "medium",
    });

  const steps: Array<Record<string, unknown>> = [];
  let firstFailureBytes: number | null = null;
  let largestSuccessBytes = 0;

  for (const bytes of STEPS_BYTES) {
    const call = await ctrCall(ctr, "big_output", { bytes });
    const ok = field(call, "ok") === true;
    const received = Number(field(call, "received_bytes") ?? 0);
    steps.push({
      requested_bytes: bytes,
      ok,
      received_bytes: received,
      exit_code: field(call, "exit_code") ?? null,
      duration_ms: field(call, "duration_ms") ?? null,
      error: field(call, "error") ?? call.error ?? null,
      // A non-error truncation is its own finding: a cap the docs do not state.
      truncated: ok && received > 0 && received < bytes,
    });
    if (!ok || received < bytes) {
      firstFailureBytes = bytes;
      break;
    }
    largestSuccessBytes = bytes;
  }

  const noCeilingFound = firstFailureBytes === null;
  const truncatedSilently = steps.some((s) => s.truncated === true);

  return base({
    test_id: "W-CTR-08",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: largestSuccessBytes > 0 ? "accessible" : "blocked",
    severity: noCeilingFound ? "medium" : "low",
    run_id: runId,
    tags: TAGS,
    details: {
      ramp: steps,
      largest_success_bytes: largestSuccessBytes,
      first_failure_bytes: firstFailureBytes,
      no_ceiling_within_ramp: noCeilingFound,
      ramp_ceiling_bytes: STEPS_BYTES[STEPS_BYTES.length - 1],
      silent_truncation_observed: truncatedSilently,
      note: "output() is documented as a convenience over the streams, with no stated cap. Whatever bound exists is discovered at runtime, on the isolate's memory budget, driven by a process whose output volume the attacker controls (W-CTR-02 chooses the command). The failure mode is an isolate OOM attributable to container-side behaviour — and per the recorded isolate shared-fate finding, isolate OOM is not reliably confined to one caller.",
      recommendation:
        "Do not call output() on a process whose output volume is not bounded by construction. Consume `proc.stdout` as a stream with an explicit byte budget and kill() on exceed, or cap at the source (`head -c`, `-fs` limits) inside the container.",
    },
    comparison: {
      aws_lambda:
        "N/A — a spawned process's output is buffered inside the same sandbox and charged against the same memory limit, so there is no cross-boundary asymmetry to exploit.",
      azure_functions: CTR_COMPARISON.azure_functions,
      gcp_functions: CTR_COMPARISON.gcp_functions,
    },
  });
};
