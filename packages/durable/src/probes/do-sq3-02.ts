import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSq302: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQ3-02");
  await doFetch(stub, "http://do/init-schema");

  const paths = [
    ":memory:",
    "attached.db",
    "/tmp/attached.db",
    "../attached.db",
    "file::memory:?cache=shared",
  ];

  const results: Array<{ path: string; allowed: boolean; error?: string }> = [];
  for (const path of paths) {
    const data = await doFetch<{ allowed?: boolean; error?: string }>(
      stub,
      `http://do/attach-db?path=${encodeURIComponent(path)}`,
    );
    results.push({
      path,
      allowed: data.allowed ?? false,
      error: data.error,
    });
  }

  const anyAllowed = results.some((r) => r.allowed);

  return base({
    test_id: "DO-SQ3-02",
    track: "durable",
    description: "Attempt ATTACH DATABASE to access other databases or files",
    result: anyAllowed ? "accessible" : "blocked",
    severity: anyAllowed ? "high" : "informational",
    run_id: runId,
    details: { results },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
