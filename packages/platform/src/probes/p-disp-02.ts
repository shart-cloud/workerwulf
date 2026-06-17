import { dispatcher, namespaceMode } from "./_helpers.js";
import { base } from "./_helpers.js";
import type { Probe } from "./index.js";

export const pDisp02: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const existing = await probeName(c, "tenant-victim", mode);
  const missingName = `missing-${c.runId.slice(0, 8)}`;
  const missing = await probeName(c, missingName, mode);
  const timingDeltaMs = Math.abs(existing.elapsed_ms - missing.elapsed_ms);
  const distinguishable = existing.status !== missing.status || existing.threw !== missing.threw || /not found/i.test(missing.error ?? "");

  return base({
    test_id: "P-DISP-02",
    track: "platform",
    description: "Sibling-script enumeration oracle through dispatch namespace get/fetch behavior",
    result: distinguishable ? "partial" : "blocked",
    severity: distinguishable ? "low" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      names_probed: ["tenant-victim", missingName],
      internal_dispatch_oracle: { existing, missing, distinguishable },
      timing_oracle_ms_delta: timingDeltaMs,
      external_status_oracle: { tested: false, reason: "current dispatch Worker exposes probes, not tenant-name routing" },
      note: distinguishable
        ? "Script existence is distinguishable to platform dispatch code; keep customer-facing routing responses uniform."
        : "No distinguishable script-existence signal observed through this dispatch path.",
    },
  });
};

async function probeName(c: Parameters<Probe>[0], name: string, mode: "trusted" | "untrusted") {
  const ns = dispatcher(c.env, mode);
  const started = Date.now();
  try {
    const fetcher = ns.get(name, {}, { outbound: { customer_name: name, url: c.req.url, run_id: c.runId, test_id: "P-DISP-02" } });
    const res = await fetcher.fetch(new Request(`https://${name}.wulf.invalid/cmd/health`));
    return { name, threw: false, status: res.status, elapsed_ms: Date.now() - started, body_prefix: (await res.text()).slice(0, 160) };
  } catch (err) {
    return { name, threw: true, elapsed_ms: Date.now() - started, error: err instanceof Error ? err.message : String(err) };
  }
}
