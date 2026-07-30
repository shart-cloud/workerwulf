import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, execOf, field, stdoutOf } from "./_ctr.js";

const DESCR =
  "Worker vars/secrets inheritance into exec'd container processes — env harvest and caller override";
const TARGET = "ContainerStartupOptions.env / ContainerExecOptions.env / /proc/1/environ";
const TAGS = ["container", "container:exec", "secret", "misconfig:secret"];

/**
 * W-CTR-04 — the Serverless Prey env-harvest step, re-asked one boundary over.
 *
 * On Lambda/Azure/GCP, "read the function's environment" is the canonical first move
 * after code execution, because credentials live there. Cloudflare Workers deliberately
 * do NOT expose secrets as process env — there is no process. Containers reintroduce
 * one, and the container's env is populated from Worker config
 * (`ContainerStartupOptions.env` / the Container helper's `envVars`).
 *
 * Three questions:
 *   1. Do Worker-side vars and secrets land in an exec'd process's environment?
 *   2. Can the *caller* of exec() override them via `ContainerExecOptions.env` —
 *      i.e. can request-derived data rewrite a variable the operator set (LD_PRELOAD,
 *      PATH, an API base URL)?
 *   3. Can a child read PID 1's environment via /proc/1/environ, recovering values the
 *      caller was not given? That is the harvest path that survives a careful
 *      per-exec env allowlist.
 */
export const wCtr04: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-04",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "medium",
    });

  const call = await ctrCall(ctr, "env_probe", {
    // What an attacker who controls one exec argument would set. PATH first: a
    // rewritten PATH turns every later un-pathed command into attacker code.
    env: {
      PATH: "/tmp/evil:/usr/bin:/bin",
      WULF_CTR_VAR: `overridden-by-caller-${runId.slice(0, 8)}`,
      LD_PRELOAD: "/tmp/nonexistent-benign.so",
    },
  });

  const inherited = execOf(call, "inherited");
  const overridden = execOf(call, "overridden");
  const pid1 = execOf(call, "pid1_environ");

  const inheritedEnv = stdoutOf(inherited);
  const overriddenEnv = stdoutOf(overridden);
  const pid1Env = stdoutOf(pid1);

  const varInherited = /WULF_CTR_VAR=flag\{w-ctr-04-worker-var\}/.test(inheritedEnv);
  const secretInherited = /WULF_CTR_SECRET=flag\{w-ctr-04-worker-secret\}/.test(inheritedEnv);
  const callerOverrode = overriddenEnv.includes(`overridden-by-caller-${runId.slice(0, 8)}`);
  const pathOverrode = /PATH=\/tmp\/evil/.test(overriddenEnv);
  const ldPreloadAccepted = /LD_PRELOAD=/.test(overriddenEnv);
  const pid1Readable = pid1Env.includes("=") && !/No such file|Permission denied/.test(pid1Env);
  const pid1LeaksSecret = /WULF_CTR_SECRET=flag\{/.test(pid1Env);

  // The compounding case: the operator scrubs the per-exec env, but the child walks
  // /proc to recover what PID 1 was started with.
  const harvestSurvivesScrub = pid1LeaksSecret;

  const anySecretReachable = secretInherited || pid1LeaksSecret;

  return base({
    test_id: "W-CTR-04",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: anySecretReachable ? "accessible" : varInherited || callerOverrode ? "partial" : "blocked",
    severity: harvestSurvivesScrub ? "high" : anySecretReachable ? "medium" : "low",
    run_id: runId,
    tags: TAGS,
    details: {
      worker_var_set: field(call, "worker_var_present_in_worker") ?? null,
      worker_secret_set: field(call, "worker_secret_present_in_worker") ?? null,
      var_visible_to_process: varInherited,
      secret_visible_to_process: secretInherited,
      caller_can_override_operator_value: callerOverrode,
      caller_can_override_path: pathOverrode,
      caller_can_set_ld_preload: ldPreloadAccepted,
      pid1_environ_readable: pid1Readable,
      pid1_environ_leaks_secret: pid1LeaksSecret,
      harvest_survives_per_exec_env_scrub: harvestSurvivesScrub,
      inherited_env: clip(inheritedEnv, 900),
      overridden_env: clip(overriddenEnv, 900),
      pid1_environ: clip(pid1Env, 900),
      proc_access: clip(stdoutOf(execOf(call, "proc_access")), 400),
      note: "Workers has no process env for secrets — that is a real platform strength, and attaching a container gives it back. A secret placed in ContainerStartupOptions.env is readable by every process in the container, including ones an attacker steers via W-CTR-02, and /proc/1/environ makes per-exec env hygiene insufficient on its own.",
      recommendation:
        "Do not pass Worker secrets into container env. Keep them in the isolate and hand the container only a short-lived, narrowly-scoped token per exec, via the `env` option — and treat the container as able to read anything PID 1 was started with. Never let request data reach PATH or LD_PRELOAD.",
      call_error: call.error ?? null,
    },
    comparison: CTR_COMPARISON,
  });
};
