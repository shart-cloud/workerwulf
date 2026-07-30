import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, recOf, stdoutOf } from "./_ctr.js";

const DESCR =
  "Containers exec() argv passthrough vs shell interpolation — the request-to-process injection sink";
const TARGET = "ctx.container.exec(argv) / sh -c";
const TAGS = ["container", "container:exec", "injection", "misconfig"];

/**
 * W-CTR-02 — argv is safe; the shell hop is the sink.
 *
 * The docs state arguments are "passed directly without shell interpretation — no
 * globbing, pipes, or variable expansion", and immediately offer `["sh","-c", …]` as
 * the way to get shell features back. Both halves are tested with the *same*
 * untrusted string, so the result is a controlled A/B rather than an assertion:
 *
 *   A. exec(["echo", "$WULF_CTR_SECRET; id"])  -> literal, no expansion, no chaining
 *   B. exec(["sh","-c", `echo ${untrusted}`])  -> expansion AND command chaining
 *
 * The payload is a canary-read + `id`, not a destructive command. `accessible` here
 * means the sink is live: a Worker that builds a shell string out of request data
 * hands an HTTP client arbitrary code execution in the container.
 */
export const wCtr02: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-02",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "high",
    });

  // The string an attacker would put in a query parameter. Benign by construction:
  // it reads a canary env var and prints identity — no writes, no network.
  const untrusted = `harmless; echo INJECTED-${runId.slice(0, 8)}; id; echo $WULF_CTR_VAR`;

  const argv = await ctrCall(ctr, "exec_argv", { cmd: ["echo", untrusted] });
  const shell = await ctrCall(ctr, "exec_shell", { command: `echo ${untrusted}` });

  // Metacharacter handling in argv: a glob and a redirect that would fire in a shell.
  const meta = await ctrCall(ctr, "exec_argv", { cmd: ["echo", "/etc/*", ">", "/tmp/should-not-exist"] });
  const redirectCheck = await ctrCall(ctr, "exec_argv", {
    cmd: ["sh", "-c", "test -e /tmp/should-not-exist && echo REDIRECT-HAPPENED || echo NO-REDIRECT"],
  });

  const argvStdout = stdoutOf(recOf(argv));
  const shellStdout = stdoutOf(recOf(shell));
  const metaStdout = stdoutOf(recOf(meta));
  const redirStdout = stdoutOf(recOf(redirectCheck));

  const marker = `INJECTED-${runId.slice(0, 8)}`;
  const argvLiteral = argvStdout.includes(untrusted) && !argvStdout.includes(`\n${marker}`);
  const shellExecuted = shellStdout.includes(marker) && /uid=\d+/.test(shellStdout);
  const globExpanded = metaStdout.includes("/etc/passwd") || !metaStdout.includes("/etc/*");
  const redirectHappened = redirStdout.includes("REDIRECT-HAPPENED");

  return base({
    test_id: "W-CTR-02",
    track: "worker",
    description: DESCR,
    target: TARGET,
    // The finding is the *sink*, not a platform flaw: argv behaving literally is the
    // documented, correct behaviour. `accessible` = the shell hop executes attacker
    // input end-to-end from an HTTP request.
    result: shellExecuted ? "accessible" : argvLiteral ? "blocked" : "partial",
    severity: shellExecuted ? "high" : "informational",
    run_id: runId,
    tags: TAGS,
    details: {
      untrusted_input: untrusted,
      argv_treated_literally: argvLiteral,
      argv_stdout: clip(argvStdout, 400),
      shell_executed_injection: shellExecuted,
      shell_stdout: clip(shellStdout, 400),
      glob_expanded_in_argv: globExpanded,
      redirect_happened_in_argv: redirectHappened,
      meta_stdout: clip(metaStdout, 300),
      note: "argv is a safe channel and the docs say so. The exposure is that the documented escape hatch for shell features (sh -c) is the same call, one argument away, and a Worker assembling that string from a Request has no runtime that stops it. Nothing in the Workers platform (no CSP, no validator, no AST check like the Track-4 code-gen path has) sits between the request and the process.",
      recommendation:
        "Never interpolate request-derived data into the sh -c string. Pass untrusted values as separate argv elements, or via the `env` option, and read them inside the script by name.",
    },
    comparison: CTR_COMPARISON,
  });
};
