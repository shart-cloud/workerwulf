import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, execOf, field, recOf, stdoutOf, wait } from "./_ctr.js";

const DESCR =
  "Process lifetime beyond the request — does an exec'd process outlive the invocation that spawned it?";
const TARGET = "ctx.container.exec() process lifetime / DO hibernation";
const TAGS = ["container", "container:exec", "persistence"];

/**
 * W-CTR-06 — a process with no owner.
 *
 * The docs are explicit that exec() has **no built-in timeout** and that terminating a
 * process is the caller's job (`setTimeout` + `kill()`). Worker invocations, by
 * contrast, are strictly bounded — CPU time is metered and the isolate is torn down.
 * The interesting question is what happens to a process whose spawning invocation has
 * already returned: if it keeps running, an attacker who lands one exec (W-CTR-02) has
 * a foothold that outlives the request, on a billed instance, with the container's
 * network position (W-CTR-05).
 *
 * Sequence: spawn a marked `sleep`, return, re-enter on a *separate* request, and look
 * for the marker in the process table. Then reap it. The spawned process is a plain
 * `sleep` with a bounded duration and is killed in the probe's own cleanup step — the
 * question being asked is about lifetime semantics, not about leaving anything behind.
 */
export const wCtr06: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-06",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "medium",
    });

  const marker = `wulfdetached${runId.replace(/[^a-z0-9]/gi, "").slice(0, 10)}`;

  // 1. Spawn without awaiting. The DO's op returns as soon as it has the pid.
  const spawn = await ctrCall(ctr, "spawn_detached", { seconds: 120, marker });
  const pid = field(spawn, "pid") ?? null;

  // 2. A separate round trip — the spawning request is finished by the time this runs.
  await wait(1500);
  const afterReturn = await ctrCall(ctr, "ps", { pattern: marker });
  const survivedRequest = Number(field(afterReturn, "match_count") ?? 0) > 0;

  // 3. Another gap, longer than a typical warm-path re-entry, to see whether the
  //    runtime reaps orphans between invocations of the same DO.
  await wait(6000);
  const afterGap = await ctrCall(ctr, "ps", { pattern: marker });
  const survivedGap = Number(field(afterGap, "match_count") ?? 0) > 0;

  // 4. Cleanup rail — never leave the process running, whatever the verdict. Verified
  //    with a fresh `ps`, not from the kill command's own output: `pgrep -f <marker>`
  //    matches the cleanup shell's own argv, so it can never report a clean reap.
  const reaped = await ctrCall(ctr, "kill_pid", { pid });
  // `kill_pid` returns {killed, pid, exec} — the ExecRecord is nested, not the body.
  const reapOut = stdoutOf(execOf(reaped, "exec"));
  const killReported = field(reaped, "killed") === true;
  const afterReap = await ctrCall(ctr, "ps", { pattern: marker });
  const stillListed = Number(field(afterReap, "match_count") ?? 1) > 0;
  const reapedClean = killReported && !stillListed;

  const table = execOf(afterGap, "table");

  return base({
    test_id: "W-CTR-06",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: survivedGap ? "accessible" : survivedRequest ? "partial" : "blocked",
    severity: survivedGap ? "medium" : "low",
    run_id: runId,
    tags: TAGS,
    details: {
      spawned_pid: pid,
      marker,
      survived_spawning_request: survivedRequest,
      survived_multi_second_gap: survivedGap,
      process_table_after_gap: clip(stdoutOf(table), 900),
      container_running_after_gap: field(afterGap, "container_running") ?? null,
      cleanup_reaped: reapedClean,
      cleanup_kill_reported: killReported,
      cleanup_still_listed_after_kill: stillListed,
      cleanup_output: clip(reapOut, 300),
      cleanup_table: clip(stdoutOf(execOf(afterReap, "table")), 600),
      note: "exec() has no built-in timeout by design — the caller owns termination. That makes 'forgot to kill()' the default failure mode rather than an unusual one, and a surviving process inherits everything W-CTR-01/04/05 enumerated: the env, the filesystem, and the network position, with no request in flight to attribute it to.",
      recommendation:
        "Wrap every exec in an explicit timeout + kill() in a `finally`, as this probe's own harness does, and set `ContainerStartupOptions.hardTimeout` / `setInactivityTimeout()` as a backstop so a leaked process cannot outlive the container indefinitely.",
      call_errors: { spawn: spawn.error ?? null, ps: afterGap.error ?? null, reap: reaped.error ?? null },
    },
    comparison: {
      aws_lambda:
        "Comparable: a background process can survive into a later invocation of a warm Lambda sandbox — but there it is the *function's own* sandbox, reaped with the execution environment, not a separately-billed container the function keeps alive.",
      azure_functions: CTR_COMPARISON.azure_functions,
      gcp_functions: CTR_COMPARISON.gcp_functions,
    },
  });
};
