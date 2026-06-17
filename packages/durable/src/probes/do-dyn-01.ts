import type { Probe } from "./index.js";
import { base, delegatedResult, doFetch, fetchDynamicProbe, getDoStub } from "./_helpers.js";

export const doDyn01: Probe = async ({ env, runId }) => {
  const dynamic = await fetchDynamicProbe({
    baseUrl: env.WULF_DYNAMIC_BASE_URL,
    fetcher: env.DYNAMIC_PARENT,
    testId: "D-DO-01",
    runId,
  });
  if (dynamic) {
    return delegatedResult({
      dynamic,
      testId: "DO-DYN-01",
      description: "Dynamic Worker with DO binding executing AI-generated raw SQL",
      runId,
    });
  }

  // DO-DYN-01: Deploy a Dynamic Worker with a DO binding; have AI-generated
  // code write raw SQL. This probe is a partial baseline — full implementation
  // requires loading a Dynamic Worker that receives a DO stub via env and
  // executes LLM-generated query strings.
  const stub = getDoStub(env, "PREY_DO", "DO-DYN-01");
  await doFetch(stub, "http://do/init-schema");

  // For now, simulate by sending a raw SQL query directly to the DO
  // (representing what an AI-generated Dynamic Worker might do).
  const aiQuery = "SELECT * FROM users WHERE username = 'admin' OR '1'='1'";
  const data = await doFetch<{ rows?: unknown[] }>(
    stub,
    `http://do/classic-sqli?input=${encodeURIComponent("admin' OR '1'='1")}`,
  );
  const rows = data.rows ?? [];

  return base({
    test_id: "DO-DYN-01",
    track: "durable",
    description:
      "Dynamic Worker with DO binding executing AI-generated raw SQL",
    result: "partial",
    severity: rows.length > 1 ? "high" : "informational",
    run_id: runId,
    details: {
      simulated_ai_query: aiQuery,
      row_count: rows.length,
      simulated_sqli_accessible: rows.length > 1,
      note: "Partial only: this is a direct DO call. Configure WULF_DYNAMIC_BASE_URL to delegate to packages/dynamic-parent D-DO-01.",
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
