import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wSvc02: Probe = async ({ env, runId }) => {
  const details: Record<string, unknown> = {};
  const relay = env.SVC_RELAY;

  const spoofedHeaders = {
    "CF-Connecting-IP": "6.6.6.6",
    "CF-IPCountry": "XX",
    "CF-Ray": "wulf-spoofed-ray-id",
    "CF-Visitor": '{"scheme":"http"}',
    "X-Forwarded-For": "10.0.0.1",
    "X-Real-IP": "10.0.0.1",
  };

  const reqHeaders = new Headers(spoofedHeaders);
  reqHeaders.set("X-Wulf-Spoof-Test", "true");

  try {
    const res = await relay.fetch(
      new Request("https://internal/relay", {
        headers: reqHeaders,
      }),
    );
    const body = await res.json() as { headers: Record<string, string> };
    const received = body.headers;

    // Check which spoofed headers made it through
    const spoofResults: Record<string, { sent: string; received: string; overwritten: boolean }> = {};
    for (const [k, v] of Object.entries(spoofedHeaders)) {
      const rcv = received[k.toLowerCase()] ?? received[k] ?? "stripped";
      spoofResults[k] = {
        sent: v,
        received: rcv,
        overwritten: rcv !== v,
      };
    }

    details.spoofed_headers_sent = Object.keys(spoofedHeaders);
    details.headers_received = spoofResults;
    details.spoofing_possible = Object.values(spoofResults).some(
      (r) => !r.overwritten && r.received !== "stripped",
    );
    details.custom_header_preserved =
      received["x-wulf-spoof-test"] === "true";
  } catch (err) {
    details.error = err instanceof Error ? err.message : String(err);
  }

  return base({
    test_id: "W-SVC-02",
    track: "worker",
    description: "Test whether a calling Worker can spoof Cloudflare-trusted headers via service binding",
    result: details.spoofing_possible === true ? "accessible" : "blocked",
    severity: details.spoofing_possible === true ? "high" : "informational",
    run_id: runId,
    details,
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};