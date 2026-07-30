import type { Probe } from "./index.js";
import { base } from "./_helpers.js";
import { CTR_COMPARISON, clip, ctrBlocked, ctrClient, ctrCall, field } from "./_ctr.js";

const DESCR =
  "interceptOutbound* — rerouting a container process's egress into a Worker binding, as control and as MITM primitive";
const TARGET = "container.interceptOutboundHttp/Https/Tcp/interceptAllOutboundHttp";
const TAGS = ["container", "container:egress", "network", "mitm"];

/**
 * W-CTR-10 — the same primitive is the fix for W-CTR-05 and a MITM channel.
 *
 * `interceptOutboundHttp(addr, binding)`, its HTTPS and TCP siblings, and
 * `interceptAllOutboundHttp(binding)` redirect a container's outbound connections into
 * a Worker `Fetcher`. They are present on the shipped container handle and absent from
 * the execute-commands docs page.
 *
 * Read one way this is the missing egress control: pair it with
 * `enableInternet: false` and every connection the container believes it is making
 * goes through Worker code that can allowlist, log, and strip. Read the other way, the
 * process has no way to tell — including for **HTTPS**, where a transparent redirect
 * would normally be defeated by certificate validation. Which of those two readings is
 * true is what this probe measures, per scheme.
 *
 * The sink (`InterceptSink` in packages/container) answers with a canary. A container
 * process whose curl prints that canary was rerouted. Targets are documentation
 * domains only — nothing third-party is actually contacted when interception holds.
 */
export const wCtr10: Probe = async ({ env, runId }) => {
  const ctr = ctrClient(env);
  if (!ctr)
    return ctrBlocked({
      testId: "W-CTR-10",
      description: DESCR,
      target: TARGET,
      runId,
      tags: TAGS,
      severity: "medium",
    });

  const CANARY = "flag{w-ctr-10-egress-intercepted}";
  // RFC 2606 / RFC 6761 reserved documentation domain — resolvable, and reaching it is
  // never interesting on its own, so the only signal is whether the sink answered.
  const httpAddr = "example.com:80";
  const httpsAddr = "example.com:443";

  const http = await ctrCall(ctr, "intercept", {
    mode: "http",
    addr: httpAddr,
    probe_url: "http://example.com/",
  });
  const httpBody = String((field(http, "after") as { stdout?: string } | undefined)?.stdout ?? "");
  const httpIntercepted = httpBody.includes(CANARY);
  const httpInstalled = field(http, "installed") === true;

  const https = await ctrCall(ctr, "intercept", {
    mode: "https",
    addr: httpsAddr,
    probe_url: "https://example.com/",
  });
  const httpsRec = field(https, "after") as { stdout?: string; stderr?: string; exit_code?: number } | undefined;
  const httpsBody = String(httpsRec?.stdout ?? "");
  const httpsStderr = String(httpsRec?.stderr ?? "");
  const httpsIntercepted = httpsBody.includes(CANARY);
  const httpsInstalled = field(https, "installed") === true;
  // The security question for HTTPS: if the redirect happened AND curl did not
  // complain about the certificate, TLS gave the process no signal that its
  // "end-to-end encrypted" connection terminated in someone else's code.
  const tlsComplained = /certificate|SSL|TLS/i.test(httpsStderr);
  const transparentTls = httpsIntercepted && !tlsComplained;

  const tcp = await ctrCall(ctr, "intercept", {
    mode: "tcp",
    addr: httpAddr,
    probe_url: "http://example.com/",
  });
  const tcpBody = String((field(tcp, "after") as { stdout?: string } | undefined)?.stdout ?? "");
  const tcpInstalled = field(tcp, "installed") === true;
  // Only a successful install can be credited with the interception: the HTTP rule
  // from the previous step is still in force, so an unimplemented interceptOutboundTcp
  // would otherwise inherit that rule's canary and read as a success.
  const tcpIntercepted = tcpInstalled && tcpBody.includes(CANARY);

  const all = await ctrCall(ctr, "intercept", { mode: "all", probe_url: "http://example.com/" });
  const allBody = String((field(all, "after") as { stdout?: string } | undefined)?.stdout ?? "");
  const allIntercepted = allBody.includes(CANARY);
  const allInstalled = field(all, "installed") === true;

  const anyIntercepted = httpIntercepted || httpsIntercepted || tcpIntercepted || allIntercepted;
  const anyInstalled = httpInstalled || httpsInstalled || tcpInstalled || allInstalled;

  return base({
    test_id: "W-CTR-10",
    track: "worker",
    description: DESCR,
    target: TARGET,
    result: anyIntercepted ? "accessible" : anyInstalled ? "partial" : "blocked",
    // Not a vulnerability in itself — it is a capability with two faces. The severity
    // reflects the MITM face: transparent TLS termination the process cannot detect.
    severity: transparentTls ? "medium" : "informational",
    run_id: runId,
    tags: TAGS,
    details: {
      http_installed: httpInstalled,
      http_intercepted: httpIntercepted,
      http_response: clip(httpBody, 300),
      https_installed: httpsInstalled,
      https_intercepted: httpsIntercepted,
      https_tls_error_raised: tlsComplained,
      https_transparent_to_process: transparentTls,
      https_response: clip(httpsBody, 300),
      https_stderr: clip(httpsStderr, 300),
      tcp_installed: tcpInstalled,
      tcp_intercepted: tcpIntercepted,
      all_installed: allInstalled,
      all_intercepted: allIntercepted,
      install_errors: {
        http: field(http, "error") ?? null,
        https: field(https, "error") ?? null,
        tcp: field(tcp, "error") ?? null,
        all: field(all, "error") ?? null,
      },
      note: "As a control this is the right answer to W-CTR-05: enableInternet:false plus interceptAllOutboundHttp puts a Worker in the path of everything the container does. As an exposure it means container-observed network behaviour is not evidence of anything — a process cannot distinguish a real endpoint from a Worker impersonating one, and if the HTTPS case raises no certificate error, neither can anything inside it that relies on TLS for authenticity.",
      recommendation:
        "Use it deliberately as an egress allowlist rather than leaving the container on the open internet. Do not rely on in-container TLS as proof that a dependency was actually contacted, and do not place trust decisions inside a container whose network can be redirected by the code that started it.",
    },
    comparison: {
      aws_lambda:
        "N/A — no per-function API to transparently reroute a sandbox's outbound connections into function-owned code; the equivalent is out-of-band VPC/proxy infrastructure, owned by the network team, not by the function.",
      azure_functions: CTR_COMPARISON.azure_functions,
      gcp_functions: CTR_COMPARISON.gcp_functions,
    },
  });
};
