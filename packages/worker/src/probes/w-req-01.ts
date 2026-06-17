import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wReq01: Probe = async ({ req, runId }) => {
  // request.cf — Cloudflare-injected per-request metadata. This is the big
  // platform-injected attack surface for recon: colo, ASN, country, TLS
  // fingerprint, bot management scores, JA3, client trust signals, etc.
  const cfRaw = (req as Request & { cf?: unknown }).cf;
  const cf: Record<string, unknown> = {};
  if (cfRaw && typeof cfRaw === "object") {
    for (const k of Object.keys(cfRaw as Record<string, unknown>)) {
      const v = (cfRaw as Record<string, unknown>)[k];
      cf[k] = v;
    }
    // Also catch non-enumerable / inherited keys
    let p = Object.getPrototypeOf(cfRaw);
    let depth = 0;
    while (p && p !== Object.prototype && depth < 4) {
      for (const k of Object.getOwnPropertyNames(p)) {
        if (k === "constructor" || k in cf) continue;
        try {
          cf[`(inherited)${k}`] = (cfRaw as Record<string, unknown>)[k];
        } catch {
          /* skip */
        }
      }
      p = Object.getPrototypeOf(p);
      depth++;
    }
  }

  // CF-* request headers — additional injected metadata
  const cf_headers: Record<string, string> = {};
  for (const [name, value] of req.headers.entries()) {
    if (name.toLowerCase().startsWith("cf-") || name.toLowerCase().startsWith("x-real-ip")) {
      cf_headers[name] = value;
    }
  }

  // High-value fields broken out for easier downstream analysis
  const summary: Record<string, unknown> = {
    colo: cf["colo"] ?? null,
    country: cf["country"] ?? null,
    asn: cf["asn"] ?? null,
    asOrganization: cf["asOrganization"] ?? null,
    httpProtocol: cf["httpProtocol"] ?? null,
    tlsVersion: cf["tlsVersion"] ?? null,
    tlsCipher: cf["tlsCipher"] ?? null,
    botManagement: cf["botManagement"] ?? null,
    clientTrustScore: cf["clientTrustScore"] ?? null,
    threatScore: cf["threatScore"] ?? null,
    clientTcpRtt: cf["clientTcpRtt"] ?? null,
    edgeRequestKeepAliveStatus: cf["edgeRequestKeepAliveStatus"] ?? null,
    tlsClientAuth: cf["tlsClientAuth"] ?? null,
    requestPriority: cf["requestPriority"] ?? null,
    tlsExportedAuthenticator: cf["tlsExportedAuthenticator"] ?? null,
  };

  return base({
    test_id: "W-REQ-01",
    track: "worker",
    description: "Dump platform-injected request metadata (request.cf + cf-* headers)",
    result: Object.keys(cf).length > 0 || Object.keys(cf_headers).length > 0
      ? "accessible"
      : "blocked",
    severity: "informational",
    run_id: runId,
    details: {
      cf_fields_count: Object.keys(cf).length,
      cf_summary: summary,
      cf_full: cf,
      cf_headers,
    },
    comparison: {
      aws_lambda: "API Gateway event has requestContext.identity (IP, UA, sourceIp); no TLS fingerprint or bot signals",
      azure_functions: "HTTP trigger context exposes client IP via headers; no platform-injected ASN/TLS metadata",
      gcp_functions: "HTTP trigger receives req; X-Forwarded-For only; no equivalent rich injection",
    },
  });
};
