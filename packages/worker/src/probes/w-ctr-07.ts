import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, recOf, stdoutOf } from "./_ctr.js";

const DESCR =
  "Privilege of exec'd container processes — default uid, the caller-controlled `user` option, and what root can reach";
const TARGET = "ContainerExecOptions.user / container privilege boundary";
const TAGS = ["container", "container:exec", "privilege", "recon"];

/**
 * W-CTR-07 — how much privilege comes for free.
 *
 * `ContainerExecOptions.user` lets the *caller of exec()* choose the identity the
 * process runs as, resolved against the image's passwd database. Two things follow:
 * what the default identity is (if that is root, every W-CTR-02 injection is a root
 * injection), and whether a caller who can influence exec options can *raise* it.
 *
 * Strictly enumeration — no escape attempts, nothing destructive. The write test
 * touches a path under /srv and removes it; ptrace is checked by reading
 * /proc/sys/kernel/yama/ptrace_scope and attempting nothing.
 */
export const wCtr07: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-07",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "medium",
    });

  const defaultId = await ctrCall(ctr, "exec_argv", { cmd: ["id"] });
  const asNobody = await ctrCall(ctr, "exec_argv", { cmd: ["id"], user: "nobody" });
  const asRoot = await ctrCall(ctr, "exec_argv", { cmd: ["id"], user: "root" });
  const asUid0 = await ctrCall(ctr, "exec_argv", { cmd: ["id"], user: "0" });

  // What the default identity can actually do. Each check is read-only or self-cleaning.
  const reach = await ctrCall(ctr, "exec_shell", {
    command: [
      // writable image paths outside /tmp
      `touch /srv/.wulf-write-test-${runId.slice(0, 8)} 2>/dev/null && echo WRITE:/srv:OK && rm -f /srv/.wulf-write-test-${runId.slice(0, 8)} || echo WRITE:/srv:DENIED`,
      "touch /usr/bin/.wulf-write-test 2>/dev/null && echo WRITE:/usr/bin:OK && rm -f /usr/bin/.wulf-write-test || echo WRITE:/usr/bin:DENIED",
      // ptrace policy (read the knob; do not attach)
      "echo -n 'PTRACE_SCOPE:'; cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent",
      // device nodes a container normally should not have
      "echo -n 'DEV:'; ls /dev | tr '\\n' ',' ",
      // is the kernel keyring / other namespaces shared?
      "echo -n 'USERNS:'; readlink /proc/self/ns/user; echo -n 'PIDNS:'; readlink /proc/self/ns/pid",
      // can we see other processes' memory maps (a sibling process, not a host one)?
      "echo -n 'OTHERPROC:'; ls /proc | grep -c '^[0-9]'",
      // sudo/setuid inventory — a classic local-escalation surface
      "echo -n 'SETUID:'; find /usr/bin /bin -perm -4000 -type f 2>/dev/null | head -20 | tr '\\n' ',' ",
    ].join("; "),
  });

  const out = (call: typeof defaultId): string => stdoutOf(recOf(call));
  const defaultOut = out(defaultId);
  const reachOut = out(reach);

  const defaultRoot = /uid=0\(root\)/.test(defaultOut);
  const nobodyWorked = /uid=(65534|\d+)\(nobody\)/.test(out(asNobody));
  const rootByName = /uid=0\(root\)/.test(out(asRoot));
  const rootByUid = /uid=0/.test(out(asUid0));
  const canWriteSrv = /WRITE:\/srv:OK/.test(reachOut);
  const canWriteUsrBin = /WRITE:\/usr\/bin:OK/.test(reachOut);
  const setuidBins = (reachOut.match(/SETUID:([^;]*)/) ?? [])[1]?.split(",").filter(Boolean) ?? [];
  const ptraceScope = (reachOut.match(/PTRACE_SCOPE:(\S+)/) ?? [])[1] ?? null;

  // The escalation shape: a non-root default that the *caller* can raise to root.
  const callerCanEscalate = !defaultRoot && (rootByName || rootByUid);

  return base({
    test_id: "W-CTR-07",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: defaultRoot || rootByName || rootByUid ? "accessible" : nobodyWorked ? "partial" : "blocked",
    severity: defaultRoot ? "medium" : callerCanEscalate ? "high" : "low",
    run_id: runId,
    tags: TAGS,
    details: {
      default_identity: clip(defaultOut, 200),
      default_is_root: defaultRoot,
      user_option_honoured_nobody: nobodyWorked,
      root_by_name: rootByName,
      root_by_uid_0: rootByUid,
      caller_can_escalate_to_root: callerCanEscalate,
      can_write_srv: canWriteSrv,
      can_write_usr_bin: canWriteUsrBin,
      setuid_binaries: setuidBins,
      ptrace_scope: ptraceScope,
      enumeration_output: clip(reachOut, 1200),
      note: "Two distinct exposures. If the default is root, every argv-injection finding in W-CTR-02 is a root-level finding and the writable image filesystem makes it persistent for the container's lifetime (W-CTR-06/09). If the default is not root but `user` is reachable from request-derived options, the exec call itself is the escalation primitive — the caller picks the identity.",
      recommendation:
        "Set a non-root USER in the image, pass an explicit low-privilege `user` on every exec, and never let any part of the exec options object be built from request data. Treat the container filesystem as attacker-writable wherever the exec identity can write.",
      call_errors: { id: defaultId.error ?? null, reach: reach.error ?? null },
    },
    comparison: CTR_COMPARISON,
  });
};
