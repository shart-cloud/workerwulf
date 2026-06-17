import type { Probe } from "./index.js";
import { buildControlledHostname, buildCallbackHttpTarget, forceHttps } from "@wulf/shared";
import { base } from "./_helpers.js";

export const wNet03: Probe = async ({ env, runId }) => {
  const targets = buildTargets(env, runId);
  const probes = await Promise.all(
    targets.map(async (t) => {
      const started = Date.now();
      try {
        const res = await fetch(t.url, {
          headers: { accept: "application/dns-json,text/plain,*/*" },
          signal: AbortSignal.timeout(2000),
        });
        return {
          ...t,
          reachable: true,
          status: res.status,
          latency_ms: Date.now() - started,
          body_preview: (await res.text()).slice(0, 200),
        };
      } catch (err) {
        return {
          ...t,
          reachable: false,
          latency_ms: Date.now() - started,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    }),
  );

  return base({
    test_id: "W-NET-03",
    track: "worker",
      description: "DNS resolution and non-public destination probes",
      result: "informational",
      severity: "informational",
      run_id: runId,
      details: {
        probes,
        callback_zone: env.WULF_DNS_EXFIL_ZONE ?? null,
        callback_http_base: env.WULF_CALLBACK_HTTP_BASE ?? null,
      },
    });
};

function buildTargets(
  env: { WULF_CALLBACK_HTTP_BASE?: string; WULF_DNS_EXFIL_ZONE?: string },
  runId: string,
) {
  const targets = [
    { name: "rfc1918_10", url: "http://10.0.0.1/" },
    { name: "rfc1918_192", url: "http://192.168.1.1/" },
    { name: "loopback", url: "http://127.0.0.1/" },
    { name: "ipv6_loopback", url: "http://[::1]/" },
    { name: "link_local", url: "http://169.254.42.42/" },
    { name: "nonexistent_tld", url: "http://invalid.invalid/" },
  ];

  if (env.WULF_CALLBACK_HTTP_BASE) {
    const httpTarget = buildCallbackHttpTarget({
      base: env.WULF_CALLBACK_HTTP_BASE,
      testId: "W-NET-03",
      runId,
      track: "worker",
      extra: { probe: "callback-http" },
    });
    targets.unshift(
      { name: "callback_http", url: httpTarget },
      { name: "callback_https", url: forceHttps(httpTarget) },
    );
  } else {
    targets.unshift({
      name: "public_dns_a",
      url: "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
    });
  }

  if (env.WULF_DNS_EXFIL_ZONE) {
    const host = buildControlledHostname({
      zone: env.WULF_DNS_EXFIL_ZONE,
      testId: "W-NET-03",
      runId,
      prefix: "dns",
    });
    targets.push({ name: "controlled_zone_http", url: `http://${host}/dns-check` });
  } else {
    targets.push({ name: "dns_rebind_candidate", url: "http://1.1.1.1.nip.io/" });
  }

  return targets;
}
