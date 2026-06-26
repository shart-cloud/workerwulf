const TEST_ID = "P-WL-RT-001";

export default {
  async fetch(request, env, ctx) {
    const started = Date.now();
    const url = new URL(request.url);
    const runId = url.searchParams.get("run_id") || env.RUN_ID || crypto.randomUUID();
    const egressTarget = url.searchParams.get("egress_target") || env.EGRESS_TARGET || "";
    const sinkUrl = url.searchParams.get("sink") || env.RESULT_SINK_URL || "";
    const egressProbe = await probeEgress(egressTarget);

    const result = {
      test_id: TEST_ID,
      track: "platform",
      timestamp: new Date().toISOString(),
      description: "Self-hosted workerd proof-of-life runtime probe",
      result: "informational",
      severity: "informational",
      run_id: runId,
      tags: ["wulf-operator", "runtime-fingerprint", "poc"],
      details: {
        platform: "wulf-operator",
        local_track: "runtime-fingerprint",
        hardening_profile: env.HARDENING_PROFILE || "naked",
        worker_name: env.WORKER_NAME || "workerd-rt-001",
        request_path: url.pathname,
        runtime: runtimeSnapshot(),
        globals: globalSnapshot(),
        egress_probe: egressProbe,
        expected_host_traces: [
          "workerd process start and config/script openat activity",
          ...(egressProbe.attempted ? ["connect activity for egress_probe.target"] : []),
        ],
        elapsed_ms: Date.now() - started,
      },
    };

    if (sinkUrl) {
      ctx.waitUntil(postResult(sinkUrl, result));
    }

    return Response.json(result, {
      headers: {
        "cache-control": "no-store",
      },
    });
  },
};

function runtimeSnapshot() {
  return {
    date_now: Date.now(),
    performance_now: performance.now(),
    user_agent: typeof navigator === "object" ? navigator.userAgent || null : null,
    has_cloudflare_request_metadata: false,
  };
}

function globalSnapshot() {
  const names = [
    "fetch",
    "WebSocket",
    "connect",
    "process",
    "Deno",
    "Bun",
    "navigator",
    "caches",
    "crypto",
    "WebAssembly",
  ];

  return Object.fromEntries(names.map((name) => [name, typeof globalThis[name]]));
}

async function probeEgress(target) {
  if (!target) {
    return {
      attempted: false,
      reason: "egress_target unset",
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort("probe timeout"), 1000);
  try {
    const response = await fetch(target, {
      method: "GET",
      signal: controller.signal,
    });
    return {
      attempted: true,
      target,
      ok: response.ok,
      status: response.status,
      response_type: response.type,
    };
  } catch (error) {
    return {
      attempted: true,
      target,
      error_name: error instanceof Error ? error.name : "unknown",
      message: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function postResult(sinkUrl, result) {
  try {
    await fetch(sinkUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(result),
    });
  } catch (error) {
    console.log(
      JSON.stringify({
        event: "result_sink_failed",
        test_id: TEST_ID,
        message: error instanceof Error ? error.message : String(error),
      }),
    );
  }
}
