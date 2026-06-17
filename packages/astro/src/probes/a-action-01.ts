import type { Probe } from "./index.js";
import { actionPost, base } from "./_helpers.js";

/**
 * A-ACTION-01 — Action content-type & malformed-body handling.
 *
 * `parseRequestBody` (actions/runtime/server.ts) maps TypeError→UNSUPPORTED_MEDIA_TYPE
 * and ActionError→error, but a SyntaxError from `JSON.parse` of a malformed
 * `application/json` body falls through `throw e` (line 210) → propagates → 500.
 * We send a battery (all same-origin so checkOrigin doesn't confound) and flag
 * any 5xx as an uncaught parse-path exception.
 */
export const aAction01: Probe = async ({ env, runId }) => {
  const cases: Array<{ name: string; ct?: string; body?: string }> = [
    { name: "valid-json", ct: "application/json", body: JSON.stringify({ message: "hi" }) },
    { name: "malformed-json", ct: "application/json", body: "{ not json" },
    { name: "json-wrong-shape", ct: "application/json", body: JSON.stringify({ nope: 1 }) },
    { name: "json-array", ct: "application/json", body: "[1,2,3]" },
    { name: "json-null", ct: "application/json", body: "null" },
    { name: "text-plain", ct: "text/plain", body: "hello" },
    { name: "multipart-to-json-action", ct: "multipart/form-data; boundary=x", body: "--x--" },
    { name: "no-content-type", body: "whatever" },
  ];

  const status_by_case: Record<string, number> = {};
  let anyServerError = false;
  for (const c of cases) {
    const res = await actionPost(env, "echo", { contentType: c.ct, body: c.body });
    status_by_case[c.name] = res.status;
    if (res.status >= 500) anyServerError = true;
  }

  return base({
    test_id: "A-ACTION-01",
    track: "astro",
    description: "Action endpoint content-type / malformed-body handling — expect 4xx, flag 5xx",
    target: "/_actions/echo (POST)",
    result: anyServerError ? "accessible" : "blocked",
    severity: anyServerError ? "low" : "informational",
    run_id: runId,
    details: {
      status_by_case,
      known_lead: "malformed application/json → SyntaxError rethrown (server.ts:210) → 500",
    },
  });
};
