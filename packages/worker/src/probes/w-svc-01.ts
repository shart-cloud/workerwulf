import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wSvc01: Probe = async ({ env, req, runId }) => {
  const details: Record<string, unknown> = {};
  const relay = env.SVC_RELAY;

  // Make external HTTP request (to the same relay endpoint but via internet)
  const relayUrl = "https://wulf-dynamic-parent.sharted.workers.dev/relay";
  try {
    const start = Date.now();
    const extRes = await fetch(relayUrl);
    const extBody = await extRes.json() as {
      headers: Record<string, string>;
    };
    details.external_request = {
      status: extRes.status,
      latency_ms: Date.now() - start,
      headers: extBody.headers,
    };
  } catch (err) {
    details.external_request = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Make service binding request (internal)
  try {
    const start = Date.now();
    const svcRes = await relay.fetch(
      new URL("https://internal/relay"),
    );
    const svcBody = await svcRes.json() as {
      headers: Record<string, string>;
    };
    details.service_binding_request = {
      status: svcRes.status,
      latency_ms: Date.now() - start,
      headers: svcBody.headers,
    };
  } catch (err) {
    details.service_binding_request = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Compare
  const extHeaders = (details.external_request as Record<string, unknown>)?.headers as Record<string, string> | undefined;
  const svcHeaders = (details.service_binding_request as Record<string, unknown>)?.headers as Record<string, string> | undefined;

  if (extHeaders && svcHeaders) {
    // Check for key differences
    const cfHeadersSvc = Object.keys(svcHeaders).filter((k) => k.startsWith("cf-"));
    const cfHeadersExt = Object.keys(extHeaders).filter((k) => k.startsWith("cf-"));
    details.cf_headers_via_service_binding = cfHeadersSvc;
    details.cf_headers_via_external = cfHeadersExt;
    details.cf_connecting_ip_svc = svcHeaders["cf-connecting-ip"] ?? "absent";
    details.cf_connecting_ip_ext = extHeaders["cf-connecting-ip"] ?? "absent";
    details.cf_ray_svc = svcHeaders["cf-ray"] ?? "absent";
    details.cf_ray_ext = extHeaders["cf-ray"] ?? "absent";
    details.can_distinguish_internal_vs_external =
      cfHeadersSvc.length !== cfHeadersExt.length ||
      svcHeaders["cf-connecting-ip"] !== extHeaders["cf-connecting-ip"];
  }

  return base({
    test_id: "W-SVC-01",
    track: "worker",
    description: "Compare headers received via service binding vs external HTTP call",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details,
    comparison: {
      aws_lambda: "N/A (no equivalent service binding concept)",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};