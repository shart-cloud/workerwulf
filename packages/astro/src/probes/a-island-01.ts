import type { Probe } from "./index.js";
import { base, islandPost } from "./_helpers.js";

/**
 * A-ISLAND-01 — Server-island POST body-parsing edge cases.
 *
 * The endpoint (`core/server-islands/endpoint.ts`) does `JSON.parse(body)` then
 * `Object.hasOwn(data, 'slots')`. For the JSON literal `null`, `Object.hasOwn`
 * throws a TypeError that is NOT caught (only SyntaxError / BodySizeLimitError
 * are handled) → the request 500s instead of returning a clean 400.
 *
 * Scalar bodies (123, "x", [], true) are handled gracefully (they fall through
 * to a decrypt failure → 400). We send the battery and flag any that 500.
 */
export const aIsland01: Probe = async ({ env, runId }) => {
  const bodies = ["null", "123", '"x"', "[]", "true"];
  const findings: Record<string, number> = {};
  let anyServerError = false;

  for (const body of bodies) {
    // componentId is irrelevant: getRequestData() runs before the id lookup.
    const res = await islandPost(env, "probe", body);
    findings[body] = res.status;
    if (res.status >= 500) anyServerError = true;
  }

  return base({
    test_id: "A-ISLAND-01",
    track: "astro",
    description:
      "Server-island POST with malformed top-level JSON bodies (null/scalar) — expect clean 400, flag 5xx",
    target: "/_server-islands/[name] (POST)",
    result: anyServerError ? "accessible" : "blocked",
    severity: anyServerError ? "low" : "informational",
    run_id: runId,
    details: {
      status_by_body: findings,
      expectation: "all should be 4xx; a 5xx indicates an uncaught parse-path exception",
      known_lead: "body `null` triggers Object.hasOwn(null,'slots') TypeError → 500 (endpoint.ts:87)",
    },
  });
};
