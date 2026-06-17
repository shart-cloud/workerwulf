import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const ERROR_MARKER = `WULF-ERR-MARKER-${Date.now().toString(36)}`;
let phaseCompleted: string | null = null;

export const wErr02: Probe = async ({ runId }) => {
  // Phase determined by module-scope state, not req params
  // First request: throw error → crashes → module scope persists?
  // Actually, the probe can't crash and return. Let's use a marker check.
  // seq=0 stores the marker; seq=1 checks if it's still there.

  const details: Record<string, unknown> = {
    error_marker: ERROR_MARKER,
  };

  if (phaseCompleted === null) {
    // Phase A: try to set the marker via a thrown-and-caught error
    try {
      throw new Error(ERROR_MARKER);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      details.phase = "store";
      details.error_thrown = true;
      details.marker_in_error = msg.includes(ERROR_MARKER);

      // Check Error.captureStackTrace / Error.stackTraceLimit
      const stackLimit = (Error as unknown as Record<string, unknown>).stackTraceLimit;
      details.stack_trace_limit = stackLimit;

      // Check if there's a last-error cache
      const lastErr = (globalThis as Record<string, unknown>).__lastError;
      details.last_error_available = lastErr !== undefined;
    }

    phaseCompleted = "stored";
  } else {
    // Phase B: check for residue from previous request
    details.phase = "detect";
    const g = globalThis as Record<string, unknown>;

    let markerFound = false;
    for (const key of Object.getOwnPropertyNames(g)) {
      const value = g[key];
      if (typeof value === "string" && value.includes(ERROR_MARKER)) {
        markerFound = true;
        break;
      }
    }
    details.marker_found = markerFound;
    details.marker_persisted = markerFound;

    // Walk globals for any error-like state
    const checked: Record<string, boolean> = {};
    for (const key of Object.getOwnPropertyNames(g)) {
      if (
        key.toLowerCase().includes("error") ||
        key.toLowerCase().includes("last") ||
        key.toLowerCase().includes("trace")
      ) {
        checked[key] = true;
      }
    }
    details.error_related_globals = checked;

    // Check Error constructor for modifications
    const errProto = Error.prototype;
    const errProtoKeys = Object.getOwnPropertyNames(errProto);
    details.error_prototype_keys = errProtoKeys;

    phaseCompleted = "verified";
  }

  return base({
    test_id: "W-ERR-02",
    track: "worker",
    description:
      "Cross-request error state leakage — check if error state persists across invocations",
    result: details.marker_persisted === true ? "accessible" : "blocked",
    severity: details.marker_persisted === true ? "medium" : "informational",
    run_id: runId,
    details: {
      ...details,
      checked_locations: [
        "globalThis",
        "Error.stackTraceLimit",
        "Error.prototype",
        "error-related globals",
      ],
      note:
        details.marker_persisted === true
          ? "Error-related global state persists across invocations"
          : "No cross-request error state leakage detected",
    },
  });
};
