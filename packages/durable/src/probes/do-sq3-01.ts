import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

const PRAGMAS = [
  "foreign_keys",
  "journal_mode",
  "synchronous",
  "temp_store",
  "locking_mode",
  "page_size",
  "max_page_count",
  "encoding",
  "auto_vacuum",
  "cache_size",
  "mmap_size",
  "legacy_alter_table",
  "reverse_unordered_selects",
  "query_only",
  "cell_size_check",
  "integrity_check",
  "quick_check",
  "table_info",
  "index_list",
  "index_info",
  "collation_list",
  "database_list",
  "compile_options",
  "version",
  "user_version",
  "application_id",
  "wal_checkpoint",
  "journal_size_limit",
  "case_sensitive_like",
  "recursive_triggers",
  "secure_delete",
  "writable_schema",
  "ignore_check_constraints",
];

export const doSq301: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQ3-01");
  await doFetch(stub, "http://do/init-schema");

  const allowed: string[] = [];
  const blocked: string[] = [];

  for (const pragma of PRAGMAS) {
    const data = await doFetch<{ allowed?: boolean }>(
      stub,
      `http://do/pragma-list?pragma=${encodeURIComponent(pragma)}`,
    );
    if (data.allowed) {
      allowed.push(pragma);
    } else {
      blocked.push(pragma);
    }
  }

  return base({
    test_id: "DO-SQ3-01",
    track: "durable",
    description: "Enumerate allowed PRAGMAs",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      allowed_count: allowed.length,
      blocked_count: blocked.length,
      allowed,
      blocked,
    },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
