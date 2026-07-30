import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, field } from "./_ctr.js";

const DESCR =
  "getTcpPort() reachability — declared vs exec-spawned listeners inside the container";
const TARGET = "container.getTcpPort(port)";
const TAGS = ["container", "container:exec", "network", "recon"];

/**
 * W-CTR-11 — which listeners the isolate can reach, and who gets to create them.
 *
 * `getTcpPort(port)` returns a `Fetcher` onto a port inside the container. The
 * interesting question is not the declared port — that one is the documented path —
 * but whether a port that was never declared (no `EXPOSE`, no `defaultPort`, no
 * wrangler config) is equally reachable once *something inside the container* starts
 * listening on it. If it is, then W-CTR-02's argv injection is not only code execution:
 * an attacker can stand up a service and then reach it through a Worker, which is a
 * durable channel that survives the request that created it (W-CTR-06).
 *
 * Three checks:
 *   1. the declared port (8080, busybox httpd from the image CMD) — the baseline;
 *   2. a port with nothing listening — must fail, or the Fetcher is answering for
 *      something that is not the container;
 *   3. a port stood up by exec() and never declared anywhere.
 *
 * Each listener is a static file server on a canary document; the exec-spawned one is
 * killed in the cleanup step.
 */
export const wCtr11: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-11",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "low",
    });

  // 1. Declared port — the image's own listener.
  const declared = await ctrCall(ctr, "tcp_port", { port: 8080, path: "/" });
  const declaredBody = String(field(declared, "body") ?? "");
  const declaredReachable = field(declared, "reachable") === true && declaredBody.includes("flag{w-ctr-11-declared-port}");

  // 2. A port with nothing on it — the negative control.
  const dead = await ctrCall(ctr, "tcp_port", { port: 8099, path: "/" });
  const deadReachable = field(dead, "reachable") === true && String(field(dead, "status") ?? "") !== "";

  // 3. An undeclared port, stood up from inside via exec().
  const spawned = await ctrCall(ctr, "tcp_port", { port: 9091, path: "/", spawn_listener: true });
  const spawnedBody = String(field(spawned, "body") ?? "");
  const spawnedReachable =
    field(spawned, "reachable") === true && spawnedBody.includes("flag{w-ctr-11-undeclared-port}");

  // Cleanup rail: reap the exec-spawned httpd.
  const cleanup = await ctrCall(ctr, "exec_shell", { command: "pkill -f 'httpd -f -p 9091' || true; echo cleaned" });

  return base({
    test_id: "W-CTR-11",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: spawnedReachable ? "accessible" : declaredReachable ? "partial" : "blocked",
    severity: spawnedReachable ? "medium" : "informational",
    run_id: runId,
    tags: TAGS,
    details: {
      declared_port: 8080,
      declared_reachable: declaredReachable,
      declared_status: field(declared, "status") ?? null,
      declared_body: clip(declaredBody, 200),
      dead_port: 8099,
      dead_port_answered: deadReachable,
      dead_port_error: field(dead, "error") ?? null,
      undeclared_port: 9091,
      undeclared_listener_pid: field(spawned, "listener_pid") ?? null,
      undeclared_reachable: spawnedReachable,
      undeclared_status: field(spawned, "status") ?? null,
      undeclared_body: clip(spawnedBody, 200),
      cleanup: clip(String((cleanup.body as { stdout?: string } | undefined)?.stdout ?? ""), 120),
      note: "getTcpPort() is a port-addressed channel with no declaration requirement on the container side: the wrangler config does not enumerate what is reachable, the *running container* does. Anything that can start a listener — including an injected command — decides what a Worker can talk to. The negative control matters: a dead port that answers would mean the Fetcher is not actually bound to this container.",
      recommendation:
        "Do not treat the container's port surface as fixed by configuration. Call getTcpPort() only for ports the application defined, never for a port derived from a request, and pair with W-CTR-07's non-root exec identity so injected code cannot bind new listeners in the first place.",
      call_errors: { declared: declared.error ?? null, dead: dead.error ?? null, spawned: spawned.error ?? null },
    },
    comparison: CTR_COMPARISON,
  });
};
