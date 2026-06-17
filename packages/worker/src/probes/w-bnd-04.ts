import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const SAMPLE_LIMIT = 20;
const MAX_BYTES_PER_OBJECT = 4096;

export const wBnd04: Probe = async ({ env, runId }) => {
  const bucket = env.PREY_R2;
  if (!bucket) {
    return base({
      test_id: "W-BND-04",
      track: "worker",
      description: "R2 exfil — list objects and sample bodies",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: { error: "PREY_R2 binding not present" },
    });
  }

  const t0 = Date.now();
  const listed = await bucket.list({ limit: 1000 });
  const list_ms = Date.now() - t0;

  const keys = listed.objects.map((o) => ({
    key: o.key,
    size: o.size,
    etag: o.etag,
    uploaded: o.uploaded.toISOString(),
  }));
  const sample_keys = listed.objects.slice(0, SAMPLE_LIMIT);

  const samples: Array<{
    key: string;
    size: number;
    content_type: string | null;
    body_preview: string | null;
    read_ms: number;
  }> = [];

  for (const obj of sample_keys) {
    const t1 = Date.now();
    const fetched = await bucket.get(obj.key);
    if (!fetched) continue;
    const buf = await fetched.arrayBuffer();
    const slice = buf.slice(0, MAX_BYTES_PER_OBJECT);
    let preview: string;
    try {
      preview = new TextDecoder("utf-8").decode(slice);
    } catch {
      preview = "<binary>";
    }
    samples.push({
      key: obj.key,
      size: obj.size,
      content_type: fetched.httpMetadata?.contentType ?? null,
      body_preview: preview.slice(0, 512),
      read_ms: Date.now() - t1,
    });
  }

  const exfil_hits = samples.filter(
    (s) =>
      s.body_preview != null &&
      /EXFIL-|canary|secret|password|api[-_]?key/i.test(s.body_preview),
  );

  return base({
    test_id: "W-BND-04",
    track: "worker",
    description: "R2 exfil — list objects and sample bodies",
    target: "env.PREY_R2",
    result: keys.length > 0 ? "accessible" : "informational",
    severity:
      exfil_hits.length > 0 ? "high" : keys.length > 0 ? "medium" : "informational",
    run_id: runId,
    details: {
      total_objects: keys.length,
      truncated: listed.truncated,
      list_ms,
      sampled: samples.length,
      sample_keys: keys,
      exfil_hits,
      samples,
    },
    comparison: {
      aws_lambda: "n/a — S3 access requires IAM (typically via execution role)",
      azure_functions: "n/a — Blob Storage requires SAS or RBAC",
      gcp_functions: "n/a — GCS requires service-account auth",
    },
  });
};
