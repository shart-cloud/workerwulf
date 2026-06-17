import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

const EXFIL_PATTERN = /EXFIL-|canary|secret|password|api[-_]?key/i;

export const dBnd03: Probe = async ({ env, runId }) => {
  // Forward PARENT_KV to the child as CHILD_KV. If capability handles are
  // structured-cloneable across the loader boundary, the child should be
  // able to list+get every canary the seed script wrote.
  let stub;
  try {
    stub = loadChild(env, { env: { CHILD_KV: env.PARENT_KV as unknown } });
  } catch (err) {
    return base({
      test_id: "D-BND-03",
      track: "dynamic",
      description: "KV capability forwarded to child and exercised for exfil",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: {
        forwarding_supported: false,
        error: err instanceof Error ? err.message : String(err),
      },
    });
  }

  const { body } = await invokeChild(stub, "kv-exfil", {
    binding: "CHILD_KV",
  });
  type Data = {
    binding: string;
    total_keys?: number;
    samples?: Array<{ key: string; value_preview: string | null }>;
    error?: string;
  };
  const data = (body as { ok: boolean; data: Data }).data;

  if (data.error) {
    return base({
      test_id: "D-BND-03",
      track: "dynamic",
      description: "KV capability forwarded to child and exercised for exfil",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: { forwarding_supported: false, child_error: data.error },
    });
  }

  const samples = data.samples ?? [];
  const hits = samples.filter(
    (s) => s.value_preview != null && EXFIL_PATTERN.test(s.value_preview),
  );

  return base({
    test_id: "D-BND-03",
    track: "dynamic",
    description: "KV capability forwarded to child and exercised for exfil",
    target: "env={CHILD_KV: parent.PARENT_KV}",
    result: (data.total_keys ?? 0) > 0 ? "accessible" : "informational",
    severity:
      hits.length > 0
        ? "high"
        : (data.total_keys ?? 0) > 0
          ? "medium"
          : "informational",
    run_id: runId,
    details: {
      forwarding_supported: true,
      total_keys: data.total_keys,
      sampled: samples.length,
      exfil_hits: hits,
      samples,
    },
  });
};
