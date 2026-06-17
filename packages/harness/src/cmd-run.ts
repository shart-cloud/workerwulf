import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";
import type { ProbeResult } from "@wulf/shared";

const DEFAULT_BASE_URL = "http://127.0.0.1:8787";

const TRACK_PREFIX: Record<string, string> = {
  worker: "W-",
  dynamic: "D-",
  durable: "DO-",
  ai: "AI-",
  platform: "P-",
};

export async function cmdRun(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      "base-url": { type: "string" },
      test: { type: "string" },
      track: { type: "string" },
      all: { type: "boolean", default: false },
      output: { type: "string", default: "results" },
      "run-id": { type: "string" },
      sequential: { type: "string" },
      interval: { type: "string" },
      model: { type: "string" },
      "prompt-tier": { type: "string" },
      "global-outbound": { type: "string" },
      namespace: { type: "string" },
    },
  });

  const sequential = values.sequential ? parseInt(values.sequential, 10) : 1;
  const intervalMs = values.interval ? parseInt(values.interval, 10) : 0;

  if (!values.test && !values.track && !values.all) {
    throw new Error("run: provide --all, --track, or --test");
  }

  const baseUrl =
    values["base-url"] ?? process.env.WULF_BASE_URL ?? DEFAULT_BASE_URL;
  const outputDir = values.output ?? "results";
  const runId = values["run-id"] ?? crypto.randomUUID();

  const testIds = await resolveTestIds(baseUrl, {
    test: values.test,
    track: values.track,
    all: values.all,
  });
  if (testIds.length === 0) {
    process.stderr.write("no tests matched\n");
    process.exit(2);
  }

  process.stderr.write(
    `run_id=${runId} tests=${testIds.length} base=${baseUrl}\n`,
  );

  const extraParams: Record<string, string> = {};
  if (values.model) extraParams.model = values.model;
  if (values["prompt-tier"]) extraParams.prompt_tier = values["prompt-tier"];
  if (values["global-outbound"]) extraParams.global_outbound = values["global-outbound"];
  if (values.namespace) extraParams.namespace = values.namespace;

  const results: ProbeResult[] = [];
  for (const id of testIds) {
    for (let seq = 0; seq < sequential; seq++) {
      const qsp = new URLSearchParams();
      qsp.set("run_id", runId);
      qsp.set("seq", String(seq));
      for (const [k, v] of Object.entries(extraParams)) {
        qsp.set(k, v);
      }
      const qs = qsp.toString();
      const url = `${baseUrl}/probe/${id}?${qs}`;
      const label = sequential > 1 ? `${id}[${seq}/${sequential}]` : id;
      process.stderr.write(`→ ${label} ... `);
      const t0 = Date.now();
      try {
        const res = await fetch(url);
        const text = await res.text();
        const parsed = parseJson(text);
        const body = isProbeResult(parsed)
          ? parsed
          : errorResult(id, runId, {
              error: "malformed_probe_response",
              status: res.status,
              status_text: res.statusText,
              body_preview: text.slice(0, 1000),
              parsed,
            });
        const dt = Date.now() - t0;
        process.stderr.write(`${body.result ?? "?"} (${dt}ms)\n`);
        results.push(body);
        const filename = sequential > 1
          ? `${body.test_id}-${String(seq).padStart(3, "0")}.json`
          : `${body.test_id}.json`;
        const path = resolve(outputDir, runId, filename);
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, JSON.stringify(body, null, 2));
      } catch (err) {
        const body = errorResult(id, runId, {
          error: "probe_request_failed",
          message: err instanceof Error ? err.message : String(err),
          error_name: err instanceof Error ? err.name : "unknown",
        });
        process.stderr.write(
          `error (${err instanceof Error ? err.message : err})\n`,
        );
        results.push(body);
        const filename = sequential > 1
          ? `${id}-${String(seq).padStart(3, "0")}.json`
          : `${id}.json`;
        const path = resolve(outputDir, runId, filename);
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, JSON.stringify(body, null, 2));
      }
      if (seq < sequential - 1 && intervalMs > 0) {
        await sleep(intervalMs);
      }
    }
  }

  const summary = {
    run_id: runId,
    completed_at: new Date().toISOString(),
    base_url: baseUrl,
    count: results.length,
    by_verdict: tally(results, (r) => r.result),
  };
  const summaryPath = resolve(outputDir, runId, "summary.json");
  await mkdir(dirname(summaryPath), { recursive: true });
  await writeFile(summaryPath, JSON.stringify(summary, null, 2));
  process.stderr.write(`\nsummary → ${summaryPath}\n`);
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function isProbeResult(v: unknown): v is ProbeResult {
  if (!v || typeof v !== "object") return false;
  const r = v as Partial<ProbeResult>;
  return typeof r.test_id === "string"
    && typeof r.track === "string"
    && typeof r.timestamp === "string"
    && typeof r.description === "string"
    && typeof r.result === "string"
    && typeof r.severity === "string"
    && !!r.details
    && typeof r.details === "object";
}

function errorResult(
  testId: string,
  runId: string,
  details: Record<string, unknown>,
): ProbeResult {
  return {
    test_id: testId,
    track: trackForTestId(testId),
    timestamp: new Date().toISOString(),
    description: "Probe failed before it could return a structured result",
    result: "error",
    severity: "informational",
    run_id: runId,
    details,
  };
}

function trackForTestId(testId: string): ProbeResult["track"] {
  if (testId.startsWith("DO-")) return "durable";
  if (testId.startsWith("AI-")) return "ai";
  if (testId.startsWith("D-")) return "dynamic";
  if (testId.startsWith("P-")) return "platform";
  return "worker";
}

async function resolveTestIds(
  baseUrl: string,
  opts: { test?: string; track?: string; all: boolean },
): Promise<string[]> {
  if (opts.test) return [opts.test];
  const res = await fetch(`${baseUrl}/probes`);
  const { probes } = (await res.json()) as { probes: string[] };
  if (opts.all) return probes;
  if (opts.track) {
    const prefix = TRACK_PREFIX[opts.track];
    if (!prefix) throw new Error(`unknown track: ${opts.track}`);
    return probes.filter((p) => p.startsWith(prefix));
  }
  return [];
}

function tally<T, K extends string>(
  xs: T[],
  key: (x: T) => K,
): Record<K, number> {
  const out = {} as Record<K, number>;
  for (const x of xs) {
    const k = key(x);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
