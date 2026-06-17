import type { Env } from "./index.js";

export interface ScannerVerdict {
  decision: "allow" | "block" | "human_in_the_loop_required" | string;
  reason: string;
  score: number;
  latency_ms: number;
  error?: string | null;
  matches?: string[] | null;
}

export interface LlamaFirewallScanResult {
  decision: string;
  reason: string;
  score: number;
  scanner_breakdown: Record<string, ScannerVerdict>;
  latency_ms: number;
  error?: string;
  blocked?: number;
  policy?: string;
}

interface TraceMessage {
  role: "user" | "assistant";
  content: string;
}

async function postScan(
  env: Env,
  path: string,
  body: unknown,
  endpoint: string,
): Promise<LlamaFirewallScanResult> {
  if (!env.LLAMAFIREWALL) {
    return fallback(endpoint, "LLAMAFIREWALL binding not available");
  }
  try {
    const res = await env.LLAMAFIREWALL.fetch(
      new Request(`https://llamafirewall${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    );
    if (!res.ok) {
      return fallback(endpoint, `HTTP ${res.status}: ${await res.text()}`);
    }
    return (await res.json()) as LlamaFirewallScanResult;
  } catch (err) {
    return fallback(endpoint, err instanceof Error ? err.message : String(err));
  }
}

export async function lfScanInput(
  env: Env,
  text: string,
  probe_id?: string,
  policy: "block" | "log" | "pass" = "log",
): Promise<LlamaFirewallScanResult> {
  return postScan(env, "/scan-input", { text, probe_id, policy }, "scan-input");
}

export async function lfScanOutput(
  env: Env,
  text: string,
  probe_id?: string,
  policy: "block" | "log" | "pass" = "log",
): Promise<LlamaFirewallScanResult> {
  return postScan(env, "/scan-output", { text, probe_id, policy }, "scan-output");
}

export async function lfScanTrace(
  env: Env,
  messages: TraceMessage[],
  probe_id?: string,
  policy: "block" | "log" | "pass" = "log",
): Promise<LlamaFirewallScanResult> {
  return postScan(env, "/scan-trace", { messages, probe_id, policy }, "scan-trace");
}

export async function lfReport(env: Env, probeId?: string): Promise<unknown> {
  if (!env.LLAMAFIREWALL) return { error: "no binding" };
  const url = probeId
    ? `https://llamafirewall/report?probe_id=${encodeURIComponent(probeId)}`
    : "https://llamafirewall/report";
  const res = await env.LLAMAFIREWALL.fetch(new Request(url));
  return res.json();
}

function fallback(endpoint: string, error: string): LlamaFirewallScanResult {
  return {
    decision: "allow",
    reason: `binding_error:${endpoint}`,
    score: 0,
    scanner_breakdown: {},
    latency_ms: 0,
    error,
  };
}
