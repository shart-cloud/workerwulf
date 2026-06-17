import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSq305: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQ3-05");
  await doFetch(stub, "http://do/init-schema");

  const extensions = [
    "json1",
    "fts5",
    "math",
    "uuid",
    "/etc/passwd",
    "../../../../etc/passwd",
  ];

  const results: Array<{ ext: string; allowed: boolean; error?: string }> = [];
  for (const ext of extensions) {
    const data = await doFetch<{ allowed?: boolean; error?: string }>(
      stub,
      `http://do/load-extension?ext=${encodeURIComponent(ext)}`,
    );
    results.push({
      ext,
      allowed: data.allowed ?? false,
      error: data.error,
    });
  }

  const anyAllowed = results.some((r) => r.allowed);

  return base({
    test_id: "DO-SQ3-05",
    track: "durable",
    description: "Test SQLite extension loading",
    result: anyAllowed ? "accessible" : "blocked",
    severity: anyAllowed ? "critical" : "informational",
    run_id: runId,
    details: { results },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
