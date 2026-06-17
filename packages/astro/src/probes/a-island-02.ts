import type { Probe } from "./index.js";
import { base, islandPost, targetFetch } from "./_helpers.js";

/**
 * A-ISLAND-02 — Server-island malformed-input handling & info leakage.
 *
 * Verifies the endpoint rejects malformed / plaintext-smuggling inputs with a
 * clean 4xx and does NOT leak stack traces, file paths, or the encryption key
 * in the response body/statusText.
 */
const LEAK_MARKERS = [/\/home\//i, /at Object\./, /node_modules/, /ASTRO_KEY/i, /\.astro\b/, /SubtleCrypto/i];

export const aIsland02: Probe = async ({ env, runId }) => {
  const cases: Array<{ name: string; run: () => Promise<Response> }> = [
    { name: "malformed-json", run: () => islandPost(env, "probe", "{ not json") },
    { name: "plaintext-slots", run: () => islandPost(env, "probe", { slots: { default: "x" } }) },
    { name: "plaintext-componentExport", run: () => islandPost(env, "probe", { componentExport: "default" }) },
    { name: "get-missing-params", run: () => targetFetch(env, "/_server-islands/probe") },
  ];

  const results: Record<string, { status: number; leaked: boolean; statusText: string }> = {};
  let badStatus = false;
  let anyLeak = false;

  for (const c of cases) {
    const res = await c.run();
    const text = await res.text().catch(() => "");
    const haystack = `${res.statusText}\n${text}`;
    const leaked = LEAK_MARKERS.some((re) => re.test(haystack));
    results[c.name] = { status: res.status, leaked, statusText: res.statusText };
    if (res.status < 400 || res.status >= 500) badStatus = true;
    if (leaked) anyLeak = true;
  }

  return base({
    test_id: "A-ISLAND-02",
    track: "astro",
    description: "Server-island malformed/plaintext-smuggling inputs reject cleanly without info leak",
    target: "/_server-islands/[name]",
    result: badStatus || anyLeak ? "accessible" : "blocked",
    severity: anyLeak ? "medium" : badStatus ? "low" : "informational",
    run_id: runId,
    details: { results, leak_markers_checked: LEAK_MARKERS.map(String) },
  });
};
