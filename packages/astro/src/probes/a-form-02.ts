import type { Probe } from "./index.js";
import { actionPost, base } from "./_helpers.js";

/**
 * A-FORM-02 — Malformed multipart robustness (contrast with the JSON 500 bug).
 *
 * `parseRequestBody` calls `request.formData()`; on malformed multipart the
 * runtime throws a TypeError, which the action handler maps to 415
 * (UNSUPPORTED_MEDIA_TYPE) at server.ts:207 — NOT the 500 that the JSON
 * SyntaxError path produces. This probe confirms the form path degrades cleanly.
 * Also abuses field names (__proto__/constructor/dotted) to confirm no crash /
 * no prototype walk (formDataToObject keys come from the schema, not the form).
 */
export const aForm02: Probe = async ({ env, runId }) => {
  const cases: Array<{ name: string; ct: string; body: string }> = [
    { name: "garbage-multipart", ct: "multipart/form-data; boundary=x", body: "this is not multipart at all" },
    { name: "multipart-no-boundary", ct: "multipart/form-data", body: "--x\r\njunk\r\n--x--" },
    { name: "empty-multipart", ct: "multipart/form-data; boundary=x", body: "" },
    { name: "truncated-multipart", ct: "multipart/form-data; boundary=x", body: "--x\r\nContent-Disposition: form-data; name=\"name\"" },
    { name: "proto-field-name", ct: "application/x-www-form-urlencoded", body: "__proto__=polluted&constructor=x&name=ok" },
    { name: "dotted-field-name", ct: "application/x-www-form-urlencoded", body: "a.b.c=1&name=ok" },
  ];

  const status_by_case: Record<string, number> = Object.create(null);
  let anyServerError = false;
  for (const c of cases) {
    const res = await actionPost(env, "form", { contentType: c.ct, body: c.body }); // same-origin by default
    status_by_case[c.name] = res.status;
    if (res.status >= 500) anyServerError = true;
  }

  return base({
    test_id: "A-FORM-02",
    track: "astro",
    description: "Malformed multipart + abusive field names degrade cleanly (4xx), never 5xx",
    target: "/_actions/form (POST)",
    result: anyServerError ? "accessible" : "blocked",
    severity: anyServerError ? "low" : "informational",
    run_id: runId,
    details: {
      status_by_case,
      expectation: "malformed multipart → 415 (TypeError→UNSUPPORTED_MEDIA_TYPE), not 500; field names never pollute",
      contrast: "JSON path's SyntaxError → 500 (A-ACTION-01); the form path's TypeError → 415",
    },
  });
};
