import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wErr01: Probe = async ({ runId }) => {
  const errors: Record<string, unknown>[] = [];

  // 1. Unhandled exception
  try {
    throw new Error("sensitive data: api-key-12345-secret");
  } catch (err) {
    errors.push({
      type: "unhandled_exception",
      error_name: err instanceof Error ? err.name : "unknown",
      error_message: err instanceof Error ? err.message : String(err),
      has_stack: err instanceof Error && typeof err.stack === "string",
    });
  }

  // 2. Promise rejection
  try {
    await Promise.reject(new Error("async sensitive: db-password-hunter2"));
  } catch (err) {
    errors.push({
      type: "promise_rejection",
      error_name: err instanceof Error ? err.name : "unknown",
      error_message: err instanceof Error ? err.message : String(err),
      has_stack: err instanceof Error && typeof err.stack === "string",
    });
  }

// 3. SyntaxError via JSON.parse
  try {
    JSON.parse("{broken json");
  } catch (err) {
    errors.push({
      type: "json_parse_error",
      error_name: err instanceof Error ? err.name : "unknown",
      error_message: err instanceof Error ? err.message : String(err),
    });
  }

  // 4. TypeError
  try {
    (undefined as unknown as { method(): void }).method();
  } catch (err) {
    errors.push({
      type: "type_error",
      error_name: err instanceof Error ? err.name : "unknown",
      error_message: err instanceof Error ? err.message : String(err),
    });
  }

  // 5. RangeError
  try {
    new Array(-1);
  } catch (err) {
    errors.push({
      type: "range_error",
      error_name: err instanceof Error ? err.name : "unknown",
      error_message: err instanceof Error ? err.message : String(err),
    });
  }

  // 6. URIError via malformed URI
  try {
    decodeURIComponent("%E0%A4%");
  } catch (err) {
    errors.push({
      type: "uri_error",
      error_name: err instanceof Error ? err.name : "unknown",
      error_message: err instanceof Error ? err.message : String(err),
    });
  }

  // 7. ReferenceError
  try {
    // @ts-expect-error intentional reference error test
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    nonexistentVariable;
  } catch (err) {
    errors.push({
      type: "reference_error",
      error_name: err instanceof Error ? err.name : "unknown",
      error_message: err instanceof Error ? err.message : String(err),
    });
  }

  return base({
    test_id: "W-ERR-01",
    track: "worker",
    description:
      "Trigger various error conditions and document error properties exposed within the isolate",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      errors,
      total_types_tested: errors.length,
      note: "Errors are caught internally — this documents what the runtime includes in Error objects, not what leaks to the HTTP caller",
    },
    comparison: {
      aws_lambda: "informational (Node.js error objects include full stack)",
      azure_functions: "informational (error details included in response)",
      gcp_functions: "informational (error details included in response)",
    },
  });
};