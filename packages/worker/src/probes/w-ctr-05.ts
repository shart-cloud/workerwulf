import type { Probe } from "./index.js";
import { buildCallbackHttpTarget } from "@wulf/shared";
import { base } from "./_helpers.js";
import type { ExecRecord } from "./_ctr.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, field, stdoutOf } from "./_ctr.js";

const DESCR =
  "Container egress reach vs the isolate's fetch() — arbitrary ports, raw TCP, DNS, reserved ranges, enableInternet";
const TARGET = "container process egress / ContainerStartupOptions.enableInternet";
const TAGS = ["container", "container:egress", "exfil", "network"];

interface EgressTarget {
  label: string;
  kind: "http" | "tcp" | "dns";
  target: string;
  port?: number;
}

/**
 * W-CTR-05 — the container is a second, differently-policed network position.
 *
 * A Worker's `fetch()` is a constrained egress path: HTTP(S) only, a restricted port
 * list, no raw sockets, subject to platform policy. An exec'd container process has
 * an ordinary Linux network stack: curl to any port, `nc` for raw TCP, its own DNS
 * resolver. If a Worker exposes exec() to request-shaped input (W-CTR-02), the
 * attacker's egress capability is the *container's*, not the isolate's.
 *
 * Also tests whether `ContainerStartupOptions.enableInternet: false` binds processes
 * started by exec() or only the image entrypoint — i.e. whether the one documented
 * network control actually covers this surface.
 *
 * Every target is the researcher's own callback host, loopback, or a
 * documented-reserved range. No third-party hosts, one request each, no scanning.
 */
export const wCtr05: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-05",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "high",
    });

  const callbackBase = env.WULF_CALLBACK_HTTP_BASE;
  const callbackUrl = callbackBase
    ? buildCallbackHttpTarget({
        base: callbackBase,
        testId: "W-CTR-05",
        runId,
        track: "worker",
        extra: { via: "container-exec-curl" },
      })
    : null;
  const callbackHost = callbackBase ? new URL(callbackBase).hostname : null;

  const targets: EgressTarget[] = [];
  if (callbackUrl) targets.push({ label: "own_callback_https", kind: "http", target: callbackUrl });
  if (callbackHost) {
    // A port the isolate's fetch() will not open. Reachability here is the finding —
    // one connect, no scanning.
    targets.push({ label: "own_callback_tcp_22", kind: "tcp", target: callbackHost, port: 22 });
    targets.push({ label: "own_callback_tcp_443", kind: "tcp", target: callbackHost, port: 443 });
    targets.push({ label: "own_callback_dns", kind: "dns", target: callbackHost });
  }
  // Reserved ranges: is the container on a network that can see infrastructure the
  // isolate cannot? A single connect attempt each; per the Wave 6 doc, any hit stops
  // the wave and goes to HackerOne before further probing.
  targets.push({ label: "link_local_metadata", kind: "tcp", target: "169.254.169.254", port: 80 });
  // NOT 10.0.0.1 — the first run showed that is the container's *own* address (W-CTR-11's
  // dead-port error names it), so probing it measures nothing about the wider network.
  targets.push({ label: "rfc1918_192", kind: "tcp", target: "192.168.0.1", port: 80 });
  // The container's own address on its declared port: establishes that "10.0.0.0/8 is
  // reachable" means only "itself", which is the honest reading of the previous result.
  targets.push({ label: "container_self_addr", kind: "tcp", target: "10.0.0.1", port: 8080 });
  targets.push({ label: "loopback_self", kind: "tcp", target: "127.0.0.1", port: 8080 });

  // A dedicated instance. This probe restarts the container (twice), and requests to a
  // single Durable Object are serialized — in the first Wave 6 run a restart on the
  // shared instance wedged it and every later probe queued behind it until timeout.
  // Isolating the destructive probe keeps that blast radius to itself.
  const INST = `wulf-ctr-net-${runId.slice(0, 8)}`;

  const online = await ctrCall(ctr, "egress", { targets }, INST);

  // Isolate-side control: the same two probes from Worker code, for the A/B.
  const isolate: Record<string, unknown> = {};
  if (callbackUrl) {
    try {
      const res = await fetch(callbackUrl, { headers: { "user-agent": "wulf-prey/0.0 (isolate-control)" } });
      isolate.callback_http_status = res.status;
    } catch (err) {
      isolate.callback_error = err instanceof Error ? err.message : String(err);
    }
  }
  try {
    const res = await fetch("http://169.254.169.254/", { method: "GET" });
    isolate.link_local_status = res.status;
  } catch (err) {
    isolate.link_local_error = err instanceof Error ? err.message : String(err);
  }

  // --- enableInternet: false — does the documented control bind exec'd processes? --
  const offlineRestart = await ctrCall(ctr, "restart", { enable_internet: false }, INST);
  const offline = callbackUrl
    ? await ctrCall(ctr, "egress", { targets: [{ label: "own_callback_https", kind: "http", target: callbackUrl }] }, INST)
    : null;
  // Rail: leave the container back in its normal state for the rest of the wave.
  const restored = await ctrCall(ctr, "restart", { enable_internet: true }, INST);

  const rows = (field(online, "results") ?? []) as Array<Record<string, unknown>>;
  const byLabel = (label: string) => rows.find((r) => r.label === label);
  const execStdout = (label: string): string => {
    const row = byLabel(label);
    const rec = row?.exec as { stdout?: string } | undefined;
    return rec?.stdout ?? "";
  };

  const httpOk = /^\s*(200|201|202|204)\s/.test(execStdout("own_callback_https"));
  const tcp22 = execStdout("own_callback_tcp_22").includes("OPEN");
  const tcp443 = execStdout("own_callback_tcp_443").includes("OPEN");
  const dnsOk = !execStdout("own_callback_dns").includes("NXDOMAIN");
  const linkLocal = execStdout("link_local_metadata").includes("OPEN");
  const rfc1918 = execStdout("rfc1918_192").includes("OPEN");
  const selfAddr = execStdout("container_self_addr").includes("OPEN");
  const loopback = execStdout("loopback_self").includes("OPEN");

  const offlineRows = offline ? ((field(offline, "results") ?? []) as Array<Record<string, unknown>>) : [];
  const offlineRec = offlineRows[0]?.exec as { stdout?: string } | undefined;
  const offlineStdout = offlineRec?.stdout ?? "";
  const egressSurvivedDisable = /^\s*(200|201|202|204)\s/.test(offlineStdout);

  const rawTcpBeyondIsolate = tcp22 || tcp443;
  const reservedReached = linkLocal || rfc1918;

  return base({
    test_id: "W-CTR-05",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: httpOk || rawTcpBeyondIsolate ? "accessible" : dnsOk ? "partial" : "blocked",
    severity: reservedReached || egressSurvivedDisable ? "high" : rawTcpBeyondIsolate ? "medium" : "low",
    run_id: runId,
    tags: TAGS,
    details: {
      container_http_egress: httpOk,
      container_raw_tcp_22: tcp22,
      container_raw_tcp_443: tcp443,
      container_dns_resolution: dnsOk,
      container_reached_link_local: linkLocal,
      container_reached_rfc1918: rfc1918,
      container_own_rfc1918_address_reachable: selfAddr,
      container_loopback_listener: loopback,
      isolate_control: isolate,
      raw_tcp_capability_beyond_isolate: rawTcpBeyondIsolate,
      enable_internet_false_applied: field(offlineRestart, "restarted") ?? null,
      egress_survived_enable_internet_false: egressSurvivedDisable,
      offline_probe_stdout: clip(offlineStdout, 300),
      restored_online: field(restored, "restarted") ?? null,
      raw_rows: rows.map((r) => ({
        label: r.label,
        kind: r.kind,
        target: r.target,
        port: r.port ?? null,
        stdout: clip(stdoutOf((r.exec ?? null) as ExecRecord | null), 200),
        exit_code: (r.exec as { exit_code?: number } | undefined)?.exit_code ?? null,
      })),
      note: "The exfil channel a Worker-only attacker has is fetch(): HTTPS, restricted ports, platform-policed. Through exec() the same attacker gets a general-purpose socket layer. Any control reasoning about Worker egress (allowlists built on fetch interception, the Track-4 gate's egress checks) does not extend across this boundary.",
      recommendation:
        "Treat an exec-capable container as an unrestricted egress endpoint. Start it with `enableInternet: false` and reroute what it legitimately needs through `interceptOutbound*` into a Worker that enforces the allowlist (see W-CTR-10) — a per-exec argv allowlist alone does not constrain the network.",
      call_errors: { online: online.error ?? null, offline: offline?.error ?? null },
    },
    comparison: {
      aws_lambda:
        "Comparable raw-socket capability, but it is the *function's own* sandbox — there is no isolate/container split, so no control that reasons about the function's egress can be bypassed by crossing into a second sandbox.",
      azure_functions: CTR_COMPARISON.azure_functions,
      gcp_functions: CTR_COMPARISON.gcp_functions,
    },
  });
};
