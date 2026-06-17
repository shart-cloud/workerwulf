import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const SAMPLE_LIMIT = 50;

export const wBnd03: Probe = async ({ env, runId }) => {
  const kv = env.PREY_KV;
  if (!kv) {
    return base({
      test_id: "W-BND-03",
      track: "worker",
      description: "KV exfil — enumerate keys and sample values",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: { error: "PREY_KV binding not present" },
    });
  }

  const t0 = Date.now();
  const listed = await kv.list({ limit: 1000 });
  const list_ms = Date.now() - t0;

  const keys = listed.keys.map((k) => k.name);
  const sample_keys = keys.slice(0, SAMPLE_LIMIT);

  const samples: Array<{
    key: string;
    value_preview: string | null;
    value_length: number;
    found: boolean;
  }> = [];
  const t1 = Date.now();
  for (const k of sample_keys) {
    const v = await kv.get(k);
    samples.push({
      key: k,
      found: v !== null,
      value_preview: v ? v.slice(0, 256) : null,
      value_length: v ? v.length : 0,
    });
  }
  const sample_ms = Date.now() - t1;

  // Highlight anything matching the canary pattern so the report is loud.
  const exfil_hits = samples.filter(
    (s) =>
      s.value_preview != null &&
      /EXFIL-|canary|secret|password|api[-_]?key/i.test(s.value_preview),
  );

  return base({
    test_id: "W-BND-03",
    track: "worker",
    description: "KV exfil — enumerate keys and sample values",
    target: "env.PREY_KV",
    result: keys.length > 0 ? "accessible" : "informational",
    severity:
      exfil_hits.length > 0 ? "high" : keys.length > 0 ? "medium" : "informational",
    run_id: runId,
    details: {
      total_keys: keys.length,
      list_complete: listed.list_complete,
      list_ms,
      sample_ms,
      sampled: samples.length,
      sample_keys,
      exfil_hits,
      samples,
    },
    comparison: {
      aws_lambda: "n/a — KV-equivalent is DynamoDB, requires explicit IAM perms",
      azure_functions: "n/a — Cosmos DB / Table Storage require connection strings",
      gcp_functions: "n/a — Firestore requires service-account auth",
    },
  });
};
