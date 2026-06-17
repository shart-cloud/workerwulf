import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

const EXFIL_PATTERN = /EXFIL-|canary|secret|password|api[-_]?key/i;

export const dBnd05: Probe = async ({ env, runId }) => {
  let stub;
  try {
    stub = loadChild(env, { env: { CHILD_D1: env.PARENT_D1 as unknown } });
  } catch (err) {
    return base({
      test_id: "D-BND-05",
      track: "dynamic",
      description: "D1 capability forwarded to child and exercised for exfil",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: {
        forwarding_supported: false,
        error: err instanceof Error ? err.message : String(err),
      },
    });
  }

  const { body } = await invokeChild(stub, "d1-exfil", {
    binding: "CHILD_D1",
  });

  type Data = {
    binding: string;
    schema?: unknown[];
    dumps?: Array<{ table: string; rows?: unknown[]; error?: string }>;
    error?: string;
  };
  const data = (body as { ok: boolean; data: Data }).data;

  if (data.error) {
    return base({
      test_id: "D-BND-05",
      track: "dynamic",
      description: "D1 capability forwarded to child and exercised for exfil",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: { forwarding_supported: false, child_error: data.error },
    });
  }

  const exfil_hit = EXFIL_PATTERN.test(JSON.stringify(data.dumps ?? []));
  const tableCount = (data.dumps ?? []).length;

  return base({
    test_id: "D-BND-05",
    track: "dynamic",
    description: "D1 capability forwarded to child and exercised for exfil",
    target: "env={CHILD_D1: parent.PARENT_D1}",
    result: tableCount > 0 ? "accessible" : "informational",
    severity:
      exfil_hit ? "high" : tableCount > 0 ? "medium" : "informational",
    run_id: runId,
    details: {
      forwarding_supported: true,
      schema: data.schema,
      table_count: tableCount,
      exfil_hit,
      dumps: data.dumps,
    },
  });
};
