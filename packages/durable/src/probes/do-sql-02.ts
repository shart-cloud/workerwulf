import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSql02: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQL-02");
  await doFetch(stub, "http://do/init-schema");

  // Attempt stacked query: inject ; DROP TABLE or ; INSERT
  const payload = "admin'; INSERT INTO users (id, username, password, secret) VALUES (99, 'attacker', 'pwned', 'stacked-flag'); SELECT * FROM users WHERE username = 'admin";
  const data = await doFetch<{ rows?: unknown[]; query?: string }>(
    stub,
    `http://do/stacked-query?input=${encodeURIComponent(payload)}`,
  );

  // Verify if the injected row exists
  const verifyData = await doFetch<{ rows?: unknown[] }>(
    stub,
    `http://do/classic-sqli?input=${encodeURIComponent("attacker")}`,
  );
  const injected = (verifyData.rows ?? []).some(
    (r: unknown) =>
      r && typeof r === "object" && (r as Record<string, unknown>).username === "attacker",
  );

  return base({
    test_id: "DO-SQL-02",
    track: "durable",
    description: "Stacked queries (multi-statement injection)",
    result: injected ? "accessible" : "blocked",
    severity: injected ? "critical" : "informational",
    run_id: runId,
    details: {
      payload,
      injected_row_found: injected,
      initial_rows: data.rows,
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
