import type { Probe } from "./index.js";
import { buildCallbackHttpTarget, forceHttps } from "@wulf/shared";
import { base } from "./_helpers.js";

export const wNet05: Probe = async ({ env, runId }) => {
  const targets = buildTargets(env, runId);
  const probes = await Promise.all(
    targets.map(async (url) => {
      const started = Date.now();
      try {
        const res = await fetch(url, {
          method: "GET",
          redirect: "manual",
          signal: AbortSignal.timeout(2500),
        });
        return {
          url,
          reachable: true,
          status: res.status,
          latency_ms: Date.now() - started,
          server: res.headers.get("server"),
          cf_ray: res.headers.get("cf-ray"),
        };
      } catch (err) {
        return {
          url,
          reachable: false,
          latency_ms: Date.now() - started,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    }),
  );

  return base({
    test_id: "W-NET-05",
    track: "worker",
      description: "Reachability of presumed-internal Cloudflare hostnames",
      result: "informational",
      severity: "informational",
      run_id: runId,
      details: {
        probes,
        callback_http_base: env.WULF_CALLBACK_HTTP_BASE ?? null,
      },
    });
};

function buildTargets(
  env: { WULF_CALLBACK_HTTP_BASE?: string },
  runId: string,
): string[] {
  const targets = [
    "http://localhost/",
    "http://metadata.cloudflare.com/",
    "http://colo.cloudflare.com/",
    "http://internal.cloudflare/",
  ];

  if (env.WULF_CALLBACK_HTTP_BASE) {
    const callbackTarget = buildCallbackHttpTarget({
      base: env.WULF_CALLBACK_HTTP_BASE,
      testId: "W-NET-05",
      runId,
      track: "worker",
      extra: { probe: "control" },
    });
    targets.push(callbackTarget, forceHttps(callbackTarget));
  } else {
    targets.push(
      "https://workers.cloudflare.com/",
      "https://api.cloudflare.com/",
      "https://dash.cloudflare.com/",
      "https://1.1.1.1/",
    );
  }

  return targets;
}
