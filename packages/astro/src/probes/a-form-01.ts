import type { Probe } from "./index.js";
import { actionPost, base, multipartBody, urlencodedBody } from "./_helpers.js";

/**
 * A-FORM-01 — Form-action content-type / accept / CSRF matrix.
 *
 * The `form` action (accept: "form", input { name }) must:
 *  - accept same-origin urlencoded + multipart (200),
 *  - reject JSON body (415 — not FormData),
 *  - reject cross-origin form POSTs (403 — origin check, form content-type),
 *  - reject missing required field (400 — zod).
 */
export const aForm01: Probe = async ({ env, runId }) => {
  const ue = urlencodedBody({ name: "alice" });
  const mp = multipartBody({ name: "alice" });
  const ueEmpty = urlencodedBody({ nope: "x" });

  const checks: Array<{ name: string; run: () => Promise<Response>; want: number }> = [
    { name: "same-origin-urlencoded", want: 200, run: () => actionPost(env, "form", { ...ue }) },
    { name: "same-origin-multipart", want: 200, run: () => actionPost(env, "form", { ...mp }) },
    { name: "json-to-form-action", want: 415, run: () => actionPost(env, "form", { contentType: "application/json", body: JSON.stringify({ name: "a" }) }) },
    { name: "cross-origin-no-origin", want: 403, run: () => actionPost(env, "form", { ...ue, sameOrigin: false }) },
    { name: "cross-origin-evil", want: 403, run: () => actionPost(env, "form", { ...ue, origin: "http://evil.example" }) },
    { name: "missing-required-field", want: 400, run: () => actionPost(env, "form", { ...ueEmpty }) },
  ];

  const results: Record<string, { status: number; want: number; ok: boolean }> = {};
  let allOk = true;
  for (const c of checks) {
    const res = await c.run();
    const ok = res.status === c.want;
    results[c.name] = { status: res.status, want: c.want, ok };
    if (!ok) allOk = false;
  }

  return base({
    test_id: "A-FORM-01",
    track: "astro",
    description: "Form-action content-type/accept enforcement + CSRF (cross-origin form → 403)",
    target: "/_actions/form (POST)",
    result: allOk ? "blocked" : "accessible",
    severity: allOk ? "informational" : "medium",
    run_id: runId,
    details: { results, note: "cross-origin form must 403; only same-origin form is accepted" },
  });
};
