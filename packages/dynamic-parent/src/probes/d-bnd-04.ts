import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

const EXFIL_PATTERN = /EXFIL-|canary|secret|password|api[-_]?key/i;

export const dBnd04: Probe = async ({ env, runId }) => {
  let stub;
  try {
    stub = loadChild(env, { env: { CHILD_R2: env.PARENT_R2 as unknown } });
  } catch (err) {
    return base({
      test_id: "D-BND-04",
      track: "dynamic",
      description: "R2 capability forwarded to child and exercised for exfil",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: {
        forwarding_supported: false,
        error: err instanceof Error ? err.message : String(err),
      },
    });
  }

  const { body } = await invokeChild(stub, "r2-exfil", {
    binding: "CHILD_R2",
  });

  type Data = {
    binding: string;
    total_objects?: number;
    sample_keys?: Array<{ key: string; size: number }>;
    samples?: Array<{ key: string; body_preview: string }>;
    error?: string;
  };
  const data = (body as { ok: boolean; data: Data }).data;

  if (data.error) {
    return base({
      test_id: "D-BND-04",
      track: "dynamic",
      description: "R2 capability forwarded to child and exercised for exfil",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: { forwarding_supported: false, child_error: data.error },
    });
  }

  const samples = data.samples ?? [];
  const hits = samples.filter(
    (s) => s.body_preview != null && EXFIL_PATTERN.test(s.body_preview),
  );

  return base({
    test_id: "D-BND-04",
    track: "dynamic",
    description: "R2 capability forwarded to child and exercised for exfil",
    target: "env={CHILD_R2: parent.PARENT_R2}",
    result: (data.total_objects ?? 0) > 0 ? "accessible" : "informational",
    severity:
      hits.length > 0
        ? "high"
        : (data.total_objects ?? 0) > 0
          ? "medium"
          : "informational",
    run_id: runId,
    details: {
      forwarding_supported: true,
      total_objects: data.total_objects,
      sampled: samples.length,
      exfil_hits: hits,
      sample_keys: data.sample_keys,
      samples,
    },
  });
};
