import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSql04: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQL-04");
  await doFetch(stub, "http://do/init-schema");

  // Boolean-based blind: 'admin' AND 1=1 vs 'admin' AND 1=2
  const truePayload = "admin' AND 1=1 --";
  const falsePayload = "admin' AND 1=2 --";

  const trueData = await doFetch<{ row_count?: number }>(
    stub,
    `http://do/blind-bool?input=${encodeURIComponent(truePayload)}`,
  );
  const trueCount = trueData.row_count ?? 0;

  const falseData = await doFetch<{ row_count?: number }>(
    stub,
    `http://do/blind-bool?input=${encodeURIComponent(falsePayload)}`,
  );
  const falseCount = falseData.row_count ?? 0;

  const boolInjectable = trueCount > 0 && falseCount === 0;

  // Time-based blind: inject randomblob(100000000) to cause delay
  const timePayload = "admin' AND randomblob(100000000) --";
  const t0 = Date.now();
  await doFetch(
    stub,
    `http://do/blind-time?input=${encodeURIComponent(timePayload)}`,
  );
  const timeElapsed = Date.now() - t0;
  const timeInjectable = timeElapsed > 500; // >500ms suggests delay worked

  return base({
    test_id: "DO-SQL-04",
    track: "durable",
    description: "Blind SQL injection (boolean-based and time-based)",
    result: boolInjectable || timeInjectable ? "accessible" : "blocked",
    severity: boolInjectable || timeInjectable ? "high" : "informational",
    run_id: runId,
    details: {
      boolean: {
        true_payload: truePayload,
        true_count: trueCount,
        false_payload: falsePayload,
        false_count: falseCount,
        injectable: boolInjectable,
      },
      time: {
        payload: timePayload,
        elapsed_ms: timeElapsed,
        injectable: timeInjectable,
      },
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
