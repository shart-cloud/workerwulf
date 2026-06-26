#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    "probe-result": { type: "string" },
    "tetragon-log": { type: "string" },
    "pod-name": { type: "string" },
    namespace: { type: "string", default: "wulf-system" },
    output: { type: "string" },
    "workerd-version": { type: "string" },
    "v8-version": { type: "string" },
    "node-name": { type: "string" },
    since: { type: "string" },
    until: { type: "string" },
  },
});

if (!values["probe-result"]) {
  throw new Error("missing --probe-result");
}
if (!values["tetragon-log"]) {
  throw new Error("missing --tetragon-log");
}

const probeResult = JSON.parse(await readFile(values["probe-result"], "utf8"));
const tetragonText = await readFile(values["tetragon-log"], "utf8");
const events = parseJsonLines(tetragonText);
const namespace = values.namespace ?? "wulf-system";
const requestedPod = values["pod-name"];
const since = values.since ? Date.parse(values.since) : null;
const until = values.until ? Date.parse(values.until) : null;
const matchingEvents = events
  .map(normalizeTetragonEvent)
  .filter((event) => event && event.pod_namespace === namespace)
  .filter((event) => !requestedPod || event.pod_name === requestedPod)
  .filter((event) => withinWindow(event, since, until));

const firstEvent = matchingEvents[0];
const row = {
  observation_id: randomUUID(),
  run_id: probeResult.run_id ?? null,
  test_id: probeResult.test_id,
  track: probeResult.track,
  timestamp: probeResult.timestamp,
  platform: probeResult.details?.platform ?? "wulf-operator",
  local_track: probeResult.details?.local_track ?? null,
  hardening_profile: probeResult.details?.hardening_profile ?? null,
  worker_name: probeResult.details?.worker_name ?? null,
  pod_name: requestedPod ?? firstEvent?.pod_name ?? null,
  node_name: values["node-name"] ?? firstEvent?.node_name ?? null,
  workerd_version: values["workerd-version"] ?? null,
  v8_version: values["v8-version"] ?? null,
  probe_result: probeResult,
  host_trace: summarizeHostTrace(matchingEvents),
  metadata: {
    collector: "wulf-operator/scripts/collect-observation.mjs",
    collected_at: new Date().toISOString(),
    tetragon_event_count: matchingEvents.length,
    since: values.since ?? null,
    until: values.until ?? null,
  },
};

const output = `${JSON.stringify(row)}\n`;
if (values.output) {
  await writeFile(values.output, output);
} else {
  process.stdout.write(output);
}

function parseJsonLines(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
}

function normalizeTetragonEvent(event) {
  const kprobe = event.process_kprobe;
  const exec = event.process_exec;
  const payload = kprobe ?? exec;
  const process = payload?.process;
  const pod = process?.pod;
  if (!payload || !process || !pod) return null;

  return {
    type: kprobe ? "process_kprobe" : "process_exec",
    time: event.time ?? null,
    node_name: event.node_name ?? null,
    pod_namespace: pod.namespace ?? null,
    pod_name: pod.name ?? null,
    workload: pod.workload ?? null,
    workload_kind: pod.workload_kind ?? null,
    binary: process.binary ?? null,
    arguments: process.arguments ?? null,
    function_name: kprobe?.function_name ?? null,
    policy_name: kprobe?.policy_name ?? null,
    args: normalizeKprobeArgs(kprobe?.args ?? []),
  };
}

function withinWindow(event, since, until) {
  if (!since && !until) return true;
  if (!event.time) return false;
  const t = Date.parse(event.time);
  if (Number.isNaN(t)) return false;
  if (since && t < since) return false;
  if (until && t > until) return false;
  return true;
}

function normalizeKprobeArgs(args) {
  return args.map((arg) => {
    if (arg.string_arg !== undefined) return { type: "string", value: arg.string_arg };
    if (arg.int_arg !== undefined) return { type: "int", value: arg.int_arg };
    if (arg.sockaddr_arg !== undefined) {
      return {
        type: "sockaddr",
        family: arg.sockaddr_arg.family ?? null,
        address: arg.sockaddr_arg.addr ?? null,
        port: arg.sockaddr_arg.port ?? null,
      };
    }
    return { type: "unknown", value: arg };
  });
}

function summarizeHostTrace(events) {
  const byFunction = {};
  const destinations = [];
  const files = [];

  for (const event of events) {
    if (event.function_name) {
      byFunction[event.function_name] = (byFunction[event.function_name] ?? 0) + 1;
    }
    for (const arg of event.args) {
      if (arg.type === "sockaddr") {
        destinations.push({
          function_name: event.function_name,
          family: arg.family,
          address: arg.address,
          port: arg.port,
          time: event.time,
        });
      }
      if (arg.type === "string" && event.function_name?.includes("open")) {
        files.push({
          function_name: event.function_name,
          path: arg.value,
          time: event.time,
        });
      }
    }
  }

  return {
    source: "tetragon",
    event_count: events.length,
    by_function: byFunction,
    destinations,
    files,
    events,
  };
}
