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

const SCAN_TIMEOUT_MS = 10_000;
const TRACE_TIMEOUT_MS = 15_000;

async function postScan(
  env: Env,
  path: string,
  body: unknown,
  endpoint: string,
  policy: "block" | "log" | "pass",
  timeoutMs = SCAN_TIMEOUT_MS,
): Promise<LlamaFirewallScanResult> {
  if (!env.LLAMAFIREWALL) {
    return fallback(endpoint, "LLAMAFIREWALL binding not available", policy);
  }
  try {
    const res = await env.LLAMAFIREWALL.fetch(
      new Request(`https://llamafirewall${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      }),
    );
    if (!res.ok) {
      return fallback(endpoint, `HTTP ${res.status}: ${await res.text()}`, policy);
    }
    return (await res.json()) as LlamaFirewallScanResult;
  } catch (err) {
    return fallback(endpoint, err instanceof Error ? err.message : String(err), policy);
  }
}

export async function lfScanInput(
  env: Env,
  text: string,
  probe_id?: string,
  policy: "block" | "log" | "pass" = "log",
): Promise<LlamaFirewallScanResult> {
  return postScan(env, "/scan-input", { text, probe_id, policy }, "scan-input", policy);
}

export async function lfScanOutput(
  env: Env,
  text: string,
  probe_id?: string,
  policy: "block" | "log" | "pass" = "log",
): Promise<LlamaFirewallScanResult> {
  return postScan(env, "/scan-output", { text, probe_id, policy }, "scan-output", policy);
}

export async function lfScanTrace(
  env: Env,
  messages: TraceMessage[],
  probe_id?: string,
  policy: "block" | "log" | "pass" = "log",
): Promise<LlamaFirewallScanResult> {
  return postScan(
    env,
    "/scan-trace",
    { messages, probe_id, policy },
    "scan-trace",
    policy,
    TRACE_TIMEOUT_MS,
  );
}

export async function lfReport(env: Env, probeId?: string): Promise<unknown> {
  if (!env.LLAMAFIREWALL) return { error: "no binding" };
  const url = probeId
    ? `https://llamafirewall/report?probe_id=${encodeURIComponent(probeId)}`
    : "https://llamafirewall/report";
  const res = await env.LLAMAFIREWALL.fetch(new Request(url));
  return res.json();
}

function fallback(
  endpoint: string,
  error: string,
  policy: "block" | "log" | "pass",
): LlamaFirewallScanResult {
  // Fail closed under "block" so a degraded/timed-out scanner never allows
  // unscanned input or code through the gate (F-001).
  return {
    decision: policy === "block" ? "block" : "allow",
    reason: `binding_error:${endpoint}`,
    score: policy === "block" ? 1 : 0,
    scanner_breakdown: {},
    latency_ms: 0,
    error,
    policy,
  };
}
