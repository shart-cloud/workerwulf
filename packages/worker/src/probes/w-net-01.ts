import type { Probe } from "./index.js";
import { buildCallbackHttpTarget } from "@wulf/shared";
import { base } from "./_helpers.js";

export const wNet01: Probe = async ({ env, req, runId }) => {
  const url = new URL(req.url);
  const fallbackTarget = "https://cloudflare.com/cdn-cgi/trace";
  const resolvedTarget =
    url.searchParams.get("target") ??
    buildTarget(env, runId) ??
    fallbackTarget;

  const started = Date.now();
  try {
    const res = await fetch(resolvedTarget, {
      method: "GET",
      headers: { "user-agent": "wulf-prey/0.0" },
    });
    const text = await res.text();
    return base({
      test_id: "W-NET-01",
      track: "worker",
      description: "Outbound fetch() reachability to external host",
      target: resolvedTarget,
      result: res.ok ? "accessible" : "partial",
      severity: "informational",
      run_id: runId,
      details: {
        http_status: res.status,
        latency_ms: Date.now() - started,
        response_preview: text.slice(0, 512),
        headers: Object.fromEntries(res.headers),
      },
      comparison: {
        aws_lambda: "accessible (default VPC egress)",
        azure_functions: "accessible",
        gcp_functions: "accessible",
      },
    });
  } catch (err) {
    return base({
      test_id: "W-NET-01",
      track: "worker",
      description: "Outbound fetch() reachability to external host",
      target: resolvedTarget,
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: {
        latency_ms: Date.now() - started,
        error: err instanceof Error ? err.message : String(err),
      },
    });
  }
};

function buildTarget(
  env: { WULF_CALLBACK_HTTP_BASE?: string },
  runId: string,
): string | null {
  if (!env?.WULF_CALLBACK_HTTP_BASE) return null;
  return buildCallbackHttpTarget({
    base: env.WULF_CALLBACK_HTTP_BASE,
    testId: "W-NET-01",
    runId,
    track: "worker",
  });
}
