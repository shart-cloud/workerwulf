import type { Probe } from "./index.js";
import { base, doFetch, getDoStub } from "./_helpers.js";

/**
 * DO-MON-03 — Document available logging for DO SQL operations via Logpush.
 *
 * Probes the Cloudflare-managed Logpush R2 bucket to determine:
 * 1. Whether DO fetch events appear in workers_trace_events
 * 2. Whether SQL queries or storage operations are visible
 * 3. What fields are populated for DO-related traces
 */
export const doMon03: Probe = async ({ env, runId }) => {
  if (!env.LOGPUSH_R2) {
    return base({
      test_id: "DO-MON-03",
      track: "durable",
      description: "Document available logging for DO SQL operations",
      result: "informational",
      severity: "informational",
      run_id: runId,
      details: {
        status: "blocked",
        reason: "LOGPUSH_R2 binding not configured in wrangler.toml",
      },
      comparison: {
        aws_lambda: "CloudWatch Logs + CloudTrail",
        azure_functions: "App Insights + Diagnostic Logs",
        gcp_functions: "Cloud Logging + Cloud Audit",
      },
    });
  }

  // Step 1: Generate DO activity to create trace events
  const stub = getDoStub(env, "PREY_DO", "DO-MON-03");
  const activityStartedAt = new Date();
  const runMarker = `logpush-${runId}`.replace(/[^a-zA-Z0-9-]/g, "-");
  await doFetch(stub, "http://do/init-schema");
  await doFetch(
    stub,
    `http://do/classic-sqli?input=${encodeURIComponent(runMarker)}`,
  );
  await doFetch(stub, "http://do/sqlite-master");
  const activityEndedAt = new Date();

  // Step 2: List recent objects in the Logpush R2 bucket
  // Logpush partitions by date: YYYY/MM/DD/HH/<filename>.log.gz
  const now = new Date();
  const todayPrefix = `${now.getUTCFullYear()}/${String(now.getUTCMonth() + 1).padStart(2, "0")}/${String(now.getUTCDate()).padStart(2, "0")}/`;

  const listed = await env.LOGPUSH_R2.list({
    prefix: todayPrefix,
    limit: 50,
  });

  const objects = listed.objects.sort(
    (a, b) => b.uploaded.getTime() - a.uploaded.getTime(),
  );

  if (objects.length === 0) {
    return base({
      test_id: "DO-MON-03",
      track: "durable",
      description: "Document available logging for DO SQL operations",
      result: "informational",
      severity: "informational",
      run_id: runId,
      details: {
        logpush_bucket_binding: "LOGPUSH_R2",
        prefix_queried: todayPrefix,
        objects_found: 0,
        run_marker: runMarker,
        activity_window_utc: {
          start: activityStartedAt.toISOString(),
          end: activityEndedAt.toISOString(),
        },
        note: "No Logpush objects found for today. Logpush delivery may be delayed or bucket path differs.",
      },
      comparison: {
        aws_lambda: "CloudWatch Logs + CloudTrail",
        azure_functions: "App Insights + Diagnostic Logs",
        gcp_functions: "Cloud Logging + Cloud Audit",
      },
    });
  }

  // Step 3: Sample the most recent log files
  const samples: Array<{
    key: string;
    size: number;
    uploaded: string;
    events: unknown[];
    fields: string[];
  }> = [];

  let doEventsFound = false;
  let sqlVisible = false;
  const allFields = new Set<string>();

  for (const obj of objects.slice(0, 5)) {
    try {
      const res = await env.LOGPUSH_R2.get(obj.key);
      if (!res) continue;

      const buf = await res.arrayBuffer();
      // Logpush files are gzip-compressed
      const decompressed = await decompressGzip(buf);
      const lines = decompressed.split("\n").filter((l) => l.trim());

      const events: unknown[] = [];
      let eventFields: string[] = [];

      for (const line of lines.slice(0, 20)) {
        try {
          const evt = JSON.parse(line) as Record<string, unknown>;
          events.push(evt);
          eventFields = Object.keys(evt);
          eventFields.forEach((f) => allFields.add(f));

          // Check for DO-related events
          if (
            evt.ScriptName === "wulf-durable" ||
            (evt.Event &&
              typeof evt.Event === "object" &&
              (evt.Event as Record<string, unknown>).doId)
          ) {
            doEventsFound = true;
          }

          // Check if SQL queries are visible in logs or spans
          const logs = evt.Logs as Array<Record<string, unknown>> | undefined;
          const spans = evt.Spans as Array<Record<string, unknown>> | undefined;
          const eventJson = JSON.stringify(evt);
          const hasSql =
            JSON.stringify(logs).includes("sql") ||
            JSON.stringify(spans).includes("sql") ||
            eventJson.includes("sqlite_master") ||
            eventJson.includes("SELECT");
          if (hasSql) sqlVisible = true;
        } catch {
          // skip malformed lines
        }
      }

      samples.push({
        key: obj.key,
        size: obj.size,
        uploaded: obj.uploaded.toISOString(),
        events,
        fields: eventFields,
      });
    } catch (err) {
      samples.push({
        key: obj.key,
        size: obj.size,
        uploaded: obj.uploaded.toISOString(),
        events: [],
        fields: [],
      });
    }
  }

  return base({
    test_id: "DO-MON-03",
    track: "durable",
    description: "Document available logging for DO SQL operations",
    result: doEventsFound ? "accessible" : "informational",
    severity: doEventsFound ? "informational" : "low",
    run_id: runId,
    details: {
      logpush_bucket_binding: "LOGPUSH_R2",
      prefix_queried: todayPrefix,
      run_marker: runMarker,
      activity_window_utc: {
        start: activityStartedAt.toISOString(),
        end: activityEndedAt.toISOString(),
      },
      objects_found: objects.length,
      objects_sampled: samples.length,
      do_events_found: doEventsFound,
      sql_queries_visible: sqlVisible,
      correlation_note: "Objects are sampled from today's Logpush prefix; use run_marker/activity_window to manually validate whether sampled events correspond to this run.",
      discovered_fields: Array.from(allFields).sort(),
      samples: samples.map((s) => ({
        key: s.key,
        size: s.size,
        uploaded: s.uploaded,
        event_count: s.events.length,
        fields: s.fields,
      })),
    },
    comparison: {
      aws_lambda: "CloudWatch Logs + CloudTrail",
      azure_functions: "App Insights + Diagnostic Logs",
      gcp_functions: "Cloud Logging + Cloud Audit",
    },
  });
};

/**
 * Decompress gzip data inside a Worker using DecompressionStream.
 */
async function decompressGzip(data: ArrayBuffer): Promise<string> {
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  writer.write(new Uint8Array(data));
  writer.close();

  const chunks: Uint8Array[] = [];
  for await (const chunk of ds.readable as ReadableStream<Uint8Array>) {
    chunks.push(chunk);
  }

  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  return new TextDecoder().decode(combined);
}
