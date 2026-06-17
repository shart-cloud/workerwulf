import type { Probe } from "./index.js";
import { base, islandPost } from "./_helpers.js";

/**
 * A-ISLAND-03 — Server-island oversized-body (DoS) limit enforcement.
 *
 * `security.serverIslandBodySizeLimit` should reject bodies over the limit with
 * a 413. The target app (./target) sets a small limit (2048 bytes) so this can
 * be exercised cheaply. We send an over-limit body and expect 413.
 *
 * NOTE: the "lying Content-Length" desync variant (small CL header, larger
 * streamed body) cannot be expressed with fetch()/Request — it requires the
 * raw-socket driver (A-BODY-01, deferred). The streamed byte-counter in
 * `readBodyWithLimit` is the backstop for that case.
 */
const TARGET_LIMIT = 2048; // keep in sync with ./target astro.config security.serverIslandBodySizeLimit

export const aIsland03: Probe = async ({ env, runId }) => {
  // Valid JSON shape, padded well past the limit.
  const pad = "A".repeat(TARGET_LIMIT * 2);
  const oversized = JSON.stringify({ encryptedProps: pad, encryptedComponentExport: "", encryptedSlots: "" });
  const res = await islandPost(env, "probe", oversized);

  const enforced = res.status === 413;
  return base({
    test_id: "A-ISLAND-03",
    track: "astro",
    description: "Server-island oversized POST body is rejected (413) by serverIslandBodySizeLimit",
    target: "/_server-islands/[name] (POST)",
    result: enforced ? "blocked" : "accessible",
    severity: enforced ? "informational" : "medium",
    run_id: runId,
    details: {
      sent_bytes: oversized.length,
      configured_limit: TARGET_LIMIT,
      status: res.status,
      expectation: "413 Content Too Large",
      note: "CL-lie / Transfer-Encoding desync deferred to raw-socket driver A-BODY-01",
    },
  });
};
