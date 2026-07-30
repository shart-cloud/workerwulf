import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, execOf, field, stdoutOf } from "./_ctr.js";

const DESCR =
  "Cloudflare Containers exec() surface introspection — what a Worker-reachable container process is given";
const TARGET = "ctx.container.exec() / SVC_CTR";
const TAGS = ["container", "container:exec", "recon"];

/**
 * W-CTR-01 — baseline map of the container execution environment.
 *
 * The Serverless Prey question ("what does the execution environment hand an attacker
 * who lands code inside it?") re-asked against a surface that did not exist when that
 * methodology was published: a POSIX process, spawned on demand by isolate code, in a
 * sandbox whose lifecycle the same isolate controls.
 *
 * Records the API surface actually present on the container handle — including the
 * three methods the public docs page omits (`inspect`, `interceptOutboundTcp`,
 * `snapshotContainer`) — plus uid/caps/seccomp, cgroup limits, mounts, the tool
 * inventory reachable on PATH, and the network view. Everything downstream in the
 * wave is an exploitation of something enumerated here.
 *
 * Deploy-only: needs wulf-container deployed and the container running.
 */
export const wCtr01: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr) return ctrBlocked({ testId: "W-CTR-01", description: DESCR, target: TARGET, runId, tags: TAGS });

  const call = await ctrCall(ctr, "introspect");
  const running = field(call, "container_running") === true;
  const execPresent = field(call, "exec_present") === true;
  const surface = (field(call, "api_surface") ?? {}) as Record<string, string>;

  const id = execOf(call, "id");
  const status = execOf(call, "proc_status");
  const limits = execOf(call, "limits");
  const mounts = execOf(call, "mounts");
  const tools = execOf(call, "tools");
  const network = execOf(call, "network");

  const uid0 = /uid=0\(root\)/.test(stdoutOf(id));
  const seccomp = (stdoutOf(status).match(/Seccomp:\s*(\d+)/) ?? [])[1] ?? null;
  const capEff = (stdoutOf(status).match(/CapEff:\s*([0-9a-f]+)/) ?? [])[1] ?? null;
  const absentTools = (stdoutOf(tools).match(/absent:\S+/g) ?? []).map((t) => t.replace("absent:", ""));
  const presentTools = stdoutOf(tools)
    .split("\n")
    .filter((l) => l.startsWith("/"))
    .map((l) => l.trim());

  // Undocumented-on-the-docs-page members of the handle. Their presence is what makes
  // W-CTR-09/10/11 possible at all.
  const undocumented = ["inspect", "intercept_outbound_tcp", "snapshot_container", "snapshot_directory"].filter(
    (k) => surface[k] === "function",
  );

  return base({
    test_id: "W-CTR-01",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: execPresent && running ? "accessible" : execPresent || running ? "partial" : "blocked",
    severity: "informational",
    run_id: runId,
    tags: TAGS,
    details: {
      container_running: running,
      exec_present: execPresent,
      api_surface: surface,
      undocumented_methods_present: undocumented,
      inspect: field(call, "inspect") ?? null,
      inspect_error: field(call, "inspect_error") ?? null,
      process_identity: clip(stdoutOf(id), 200),
      runs_as_root: uid0,
      seccomp_mode: seccomp,
      cap_eff: capEff,
      proc_status: clip(stdoutOf(status)),
      cgroup_limits: clip(stdoutOf(limits)),
      mounts: clip(stdoutOf(mounts), 1200),
      tools_present: presentTools,
      tools_absent: absentTools,
      network_view: clip(stdoutOf(network), 900),
      started_with: field(call, "started_with") ?? null,
      call_error: call.error ?? null,
      note: "Uid, capability set, seccomp mode and mount table describe the *second* sandbox the isolate can reach into. Anything permissive here is a blast-radius multiplier for W-CTR-02 (argv injection) — that is the pairing the wave is built around.",
    },
    comparison: CTR_COMPARISON,
  });
};
