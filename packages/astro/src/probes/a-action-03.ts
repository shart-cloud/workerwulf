import type { Probe } from "./index.js";
import { actionPost, base } from "./_helpers.js";

/**
 * A-ACTION-03 — Action-name path resolution / prototype-pollution guard.
 *
 * Action names are resolved as dot-separated paths against the actions object
 * (base-pipeline). `FORBIDDEN_PATH_KEYS` (__proto__, constructor, prototype)
 * must be rejected so a caller can't walk the prototype chain or pollute it.
 * Expect NOT_FOUND/4xx — never 200 (reached something) or 5xx (uncaught).
 */
export const aAction03: Probe = async ({ env, runId }) => {
  const names = [
    "__proto__",
    "constructor",
    "prototype",
    "nested.__proto__",
    "nested.constructor.name",
    "__proto__.polluted",
    "toString",
    "hasOwnProperty",
  ];

  // Null-proto: keys include `__proto__`, which on a plain {} would set the
  // prototype instead of an own property (the very footgun under test).
  const status_by_name = Object.create(null) as Record<string, number>;
  let reachedOrCrashed = false;
  for (const name of names) {
    const res = await actionPost(env, name, {
      contentType: "application/json",
      body: JSON.stringify({ polluted: true, message: "x" }),
    });
    status_by_name[name] = res.status;
    // 200 = resolved to a callable (bad); 5xx = uncaught (bad). 4xx = correctly rejected.
    if (res.status === 200 || res.status >= 500) reachedOrCrashed = true;
  }

  return base({
    test_id: "A-ACTION-03",
    track: "astro",
    description: "Action-name path traversal (__proto__/constructor/prototype) is rejected, not resolved",
    target: "/_actions/<forbidden-path>",
    result: reachedOrCrashed ? "accessible" : "blocked",
    severity: reachedOrCrashed ? "high" : "informational",
    run_id: runId,
    details: {
      status_by_name,
      expectation: "all 4xx (NOT_FOUND); 200 = prototype walk reached a callable, 5xx = uncaught",
      guard: "FORBIDDEN_PATH_KEYS in @astrojs/internal-helpers/object",
    },
  });
};
