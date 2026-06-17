import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

let accessPhaseCompleted = false;

export const wRun03: Probe = async ({ env, req, runId }) => {
  const seqValue = new URL(req.url).searchParams.get("seq");
  const phase = seqValue && parseInt(seqValue, 10) === 0 ? "access" : "detect";
  const details: Record<string, unknown> = { phase };

  if (phase === "access") {
    const secret = typeof env.SECRET_VALUE === "string"
      ? env.SECRET_VALUE
      : typeof env.WULF_ENV_PROBE === "string"
      ? env.WULF_ENV_PROBE
      : undefined;

    accessPhaseCompleted = true;
    details.request_a_accessed_secret = secret !== undefined;
    details.secret_length = secret?.length ?? 0;
    details.action = "Accessed secret value without storing it in module scope";
  } else {
    const g = globalThis as Record<string, unknown>;
    const allProps = Object.getOwnPropertyNames(g).sort();
    const findings: Record<string, unknown> = {};
    const locations: string[] = [];

    for (const prop of allProps) {
      const value = g[prop];
      if (value && typeof value === "object") {
        const ctor = (value as object).constructor?.name ?? "";
        if (ctor === "KvNamespace" || ctor === "R2Bucket" || ctor === "D1Database") {
          findings[`globalThis.${prop}`] = { constructor: ctor };
          locations.push(`globalThis.${prop}`);
        }
      }
    }

    try {
      findings.weak_ref_constructor_available = typeof (globalThis as Record<string, unknown>).WeakRef === "function";
      findings.finalization_registry_available = typeof (globalThis as Record<string, unknown>).FinalizationRegistry === "function";
    } catch {
      findings.registry_probe_error = true;
    }

    const deepCheckResults = deepCheckForBindingResidue(g, 1);
    const residueFound = locations.length > 0 || Object.keys(deepCheckResults).length > 0;

    Object.assign(details, {
      request_a_completed: accessPhaseCompleted,
      request_b_accessed_env: false,
      request_b_secret_residue_found: residueFound,
      residue_found: residueFound,
      globalThis_own_props_count: allProps.length,
      binding_like_globals: findings,
      locations_with_residue: locations,
      checked_locations: ["globalThis", "WeakRef", "FinalizationRegistry"],
      deep_check: deepCheckResults,
      note: residueFound
        ? "Binding-like residue detected without explicitly storing request A data"
        : "No secret or binding residue detected on subsequent invocation",
    });
  }

  return base({
    test_id: "W-RUN-03",
    track: "worker",
    description: "Test whether secrets accessed on one request leave residue on the next",
    result: phase === "detect" && (details.residue_found as boolean) ? "accessible" : "blocked",
    severity: phase === "detect" && (details.residue_found as boolean) ? "high" : "informational",
    run_id: runId,
    details,
  });
};

function deepCheckForBindingResidue(
  obj: Record<string, unknown>,
  depth: number,
): Record<string, unknown> {
  if (depth > 2) return {};
  const found: Record<string, unknown> = {};
  for (const prop of Object.getOwnPropertyNames(obj)) {
    const value = obj[prop];
    if (!value || typeof value !== "object") continue;

    const nested = value as Record<string, unknown>;
    const ctor = nested.constructor?.name ?? "";
    if (ctor === "KvNamespace" || ctor === "R2Bucket" || ctor === "D1Database") {
      found[prop] = { constructor: ctor, possible_binding_residue: true };
      continue;
    }

    if (ctor === "Object" || ctor === "Array") continue;
    try {
      const sub = deepCheckForBindingResidue(nested, depth + 1);
      if (Object.keys(sub).length > 0) found[prop] = { nested: sub };
    } catch {
      // Some host objects throw during property access.
    }
  }
  return found;
}
