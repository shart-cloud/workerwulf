import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

export const doSq306: Probe = async ({ env, runId }) => {
  const stub = getDoStub(env, "PREY_DO", "DO-SQ3-06");
  await doFetch(stub, "http://do/init-schema");

  const paths = [
    "/tmp/wulf-test",
    "/dev/null",
    "wulf-test.db",
    "../wulf-test",
  ];

  const results: Array<{
    path: string;
    writefile: unknown;
    readfile: unknown;
  }> = [];
  for (const path of paths) {
    const data = await doFetch<{ writefile?: unknown; readfile?: unknown }>(
      stub,
      `http://do/file-io?path=${encodeURIComponent(path)}`,
    );
    results.push({
      path,
      writefile: data.writefile,
      readfile: data.readfile,
    });
  }

  const anyWrite = results.some(
    (r) => r.writefile === "succeeded" || (typeof r.writefile === "object" && r.writefile !== null),
  );

  return base({
    test_id: "DO-SQ3-06",
    track: "durable",
    description: "Test writefile() / readfile() SQLite functions",
    result: anyWrite ? "accessible" : "blocked",
    severity: anyWrite ? "critical" : "informational",
    run_id: runId,
    details: { results },
    comparison: {
      aws_lambda: "N/A (external DB)",
      azure_functions: "N/A (external DB)",
      gcp_functions: "N/A (external DB)",
    },
  });
};
