import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSql06: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO_SECURE", "DO-SQL-06");
  await doFetch(stub, "http://do/init-schema");

  const classicPayload = "admin' OR '1'='1";
  const stackedPayload = "admin'; INSERT INTO users (id, username, password, secret) VALUES (99, 'attacker', 'pwned', 'stacked-flag'); SELECT * FROM users WHERE username = 'admin";
  const unionPayload = "admin' UNION SELECT id, password FROM users --";
  const truePayload = "admin' AND 1=1 --";
  const falsePayload = "admin' AND 1=2 --";
  const errorPayload = "1 UNION SELECT * FROM definitely_missing_table";

  const classic = await doFetch<{ rows?: unknown[]; query?: string }>(
    stub,
    `http://do/classic-sqli?input=${encodeURIComponent(classicPayload)}`,
  );
  await doFetch(stub, `http://do/stacked-query?input=${encodeURIComponent(stackedPayload)}`);
  const attacker = await doFetch<{ rows?: unknown[] }>(
    stub,
    `http://do/classic-sqli?input=${encodeURIComponent("attacker")}`,
  );
  const union = await doFetch<{ rows?: unknown[] }>(
    stub,
    `http://do/union-inject?input=${encodeURIComponent(unionPayload)}`,
  );
  const boolTrue = await doFetch<{ row_count?: number }>(
    stub,
    `http://do/blind-bool?input=${encodeURIComponent(truePayload)}`,
  );
  const boolFalse = await doFetch<{ row_count?: number }>(
    stub,
    `http://do/blind-bool?input=${encodeURIComponent(falsePayload)}`,
  );
  const errorBased = await doFetch<{ error?: string | null }>(
    stub,
    `http://do/error-based?input=${encodeURIComponent(errorPayload)}`,
  );

  const classicRows = classic.rows ?? [];
  const stackedInserted = (attacker.rows ?? []).length > 0;
  const unionLeaked = (union.rows ?? []).some(
    (r: unknown) =>
      r &&
      typeof r === "object" &&
      typeof (r as Record<string, unknown>).username === "string" &&
      (r as Record<string, unknown>).username !== "admin" &&
      (r as Record<string, unknown>).username !== "guest",
  );
  const boolLeaked = (boolTrue.row_count ?? 0) > 0 && (boolFalse.row_count ?? 0) === 0;
  const errorLeaked = Boolean(errorBased.error);
  const leaked = classicRows.length > 1 || stackedInserted || unionLeaked || boolLeaked || errorLeaked;

  return base({
    test_id: "DO-SQL-06",
    track: "durable",
    description: "Verify parameterized ? bindings prevent all injection vectors",
    result: leaked ? "accessible" : "blocked",
    severity: leaked ? "critical" : "informational",
    run_id: runId,
    details: {
      classic: { payload: classicPayload, row_count: classicRows.length, query: classic.query },
      stacked: { payload: stackedPayload, inserted_row_found: stackedInserted },
      union: { payload: unionPayload, leaked: unionLeaked, rows: union.rows ?? [] },
      blind_boolean: {
        true_payload: truePayload,
        true_count: boolTrue.row_count ?? 0,
        false_payload: falsePayload,
        false_count: boolFalse.row_count ?? 0,
        leaked: boolLeaked,
      },
      error_based: { payload: errorPayload, error: errorBased.error, leaked: errorLeaked },
      note: "Blocked means the parameterized control resisted the implemented DO-SQL-01 through DO-SQL-05 payloads.",
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
