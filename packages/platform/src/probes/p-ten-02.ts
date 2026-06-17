import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

export const pTen02: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const requestedSamples = Number(new URL(c.req.url).searchParams.get("samples") ?? "100");
  const samples = Math.max(1, Math.min(requestedSamples, 2000));
  let foreignMarkerObserved = false;
  const markers = { prey: new Set<string>(), victim: new Set<string>() };

  for (let i = 0; i < samples; i++) {
    const tenant = i % 2 === 0 ? "tenant-prey" : "tenant-victim";
    const resp = await invokeTenant<Record<string, unknown>>(c, tenant, "isolate-marker", {}, { mode });
    if (typeof resp.body.own_marker === "string") markers[tenant === "tenant-prey" ? "prey" : "victim"].add(resp.body.own_marker);
    foreignMarkerObserved ||= resp.body.foreign_marker_observed === true;
  }

  return base({
    test_id: "P-TEN-02",
    track: "platform",
    description: "Co-tenancy and isolate-sharing detection across WfP user Workers",
    result: foreignMarkerObserved ? "accessible" : "blocked",
    severity: foreignMarkerObserved ? "critical" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      samples,
      foreign_marker_observed: foreignMarkerObserved,
      shared_isolate_detected: foreignMarkerObserved,
      distinct_prey_markers_seen: markers.prey.size,
      distinct_victim_markers_seen: markers.victim.size,
      note: "No cross-tenant module-scope marker was observed in this bounded interleaving run.",
    },
  });
};
