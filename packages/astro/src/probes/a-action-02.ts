import type { Probe } from "./index.js";
import { actionPost, base } from "./_helpers.js";

/**
 * A-ACTION-02 — Action oversized-body (DoS) limit enforcement.
 *
 * `security.actionBodySizeLimit` should reject over-limit bodies with
 * CONTENT_TOO_LARGE (413). The target sets a small limit (2048) so this is
 * cheap. Header-Content-Length path and (no-CL) streamed path are both checked.
 */
const TARGET_LIMIT = 2048; // keep in sync with ./target astro.config security.actionBodySizeLimit

export const aAction02: Probe = async ({ env, runId }) => {
  const big = JSON.stringify({ message: "A".repeat(TARGET_LIMIT * 2) });

  // 1) Honest Content-Length (fetch sets it) → early header rejection.
  const withCL = await actionPost(env, "echo", { contentType: "application/json", body: big });

  // 2) Streamed body, no Content-Length → exercises readBodyWithLimit's counter.
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(new TextEncoder().encode(big));
      c.close();
    },
  });
  const noCL = await actionPost(env, "echo", {
    contentType: "application/json",
    body: stream as unknown as BodyInit,
  });

  const enforced = withCL.status === 413 && noCL.status === 413;
  return base({
    test_id: "A-ACTION-02",
    track: "astro",
    description: "Action oversized POST body rejected (413) via actionBodySizeLimit (CL + streamed)",
    target: "/_actions/echo (POST)",
    result: enforced ? "blocked" : "accessible",
    severity: enforced ? "informational" : "medium",
    run_id: runId,
    details: {
      configured_limit: TARGET_LIMIT,
      sent_bytes: big.length,
      status_with_content_length: withCL.status,
      status_streamed_no_content_length: noCL.status,
      expectation: "both 413 Content Too Large",
    },
  });
};
