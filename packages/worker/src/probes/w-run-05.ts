import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const POLLUTION_MARKER_KEY = "__wulf_polluted";
let polluteMarkerValue: string | null = null;
let modelScopeOriginalProto = false;

export const wRun05: Probe = async ({ req, runId }) => {
  const seqValue = new URL(req.url).searchParams.get("seq");
  const seq = seqValue ? parseInt(seqValue, 10) : 0;

  const details: Record<string, unknown> = { seq };

  if (seq === 0) {
    // POLLUTE phase
    polluteMarkerValue = `wulf-marker-${Date.now().toString(36)}`;
    try {
      (Object.prototype as Record<string, unknown>)[POLLUTION_MARKER_KEY] = polluteMarkerValue;
      modelScopeOriginalProto = true;
      details.phase = "pollute";
      details.marker = polluteMarkerValue;
      details.polluted_Object_prototype = true;
    } catch (err) {
      details.phase = "pollute";
      details.polluted_Object_prototype = false;
      details.error = err instanceof Error ? err.message : String(err);
    }
  } else if (seq === 1) {
    // VERIFY phase — check if pollution persists from seq=0
    const found = ({} as Record<string, unknown>)[POLLUTION_MARKER_KEY];
    const matches = found === polluteMarkerValue;
    details.phase = "verify";
    details.pollution_persisted = found !== undefined;
    details.marker_from_pollute = polluteMarkerValue;
    details.marker_found = found;
    details.marker_matches = matches;
    details.visible_on_next_request = matches;
  } else {
    // CLEANUP phase (seq=2+)
    try {
      delete (Object.prototype as Record<string, unknown>)[POLLUTION_MARKER_KEY];
      details.phase = "cleanup";
      details.cleanup_successful = true;
    } catch (err) {
      details.phase = "cleanup";
      details.cleanup_successful = false;
      details.error = err instanceof Error ? err.message : String(err);
    }

    // Verify cleanup
    const residueCheck = ({} as Record<string, unknown>)[POLLUTION_MARKER_KEY];
    details.residue_after_cleanup = residueCheck !== undefined;
  }

  return base({
    test_id: "W-RUN-05",
    track: "worker",
    description:
      "Prototype pollution persistence — pollute Object.prototype on one request, verify on next",
    result: seq === 1 && details.pollution_persisted === true ? "accessible" : "blocked",
    severity: seq === 1 && details.pollution_persisted === true ? "high" : "informational",
    run_id: runId,
    details: {
      ...details,
      note:
        seq === 0
          ? "Pollution marker set on Object.prototype"
          : seq === 1 && details.pollution_persisted
            ? "Prototype pollution SURVIVES across invocations — a single polluted proto poisons all subsequent requests"
            : seq === 1
              ? "Prototype pollution does NOT persist — isolate resets between invocations"
              : "Cleanup complete",
    },
    comparison: {
      aws_lambda: "accessible (warm containers share proto chain)",
      azure_functions: "accessible (warm instances share proto chain)",
      gcp_functions: "accessible (warm instances share proto chain)",
    },
  });
};
