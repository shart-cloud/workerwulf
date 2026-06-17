import type { Env } from "./index.js";

export interface PromptGuardResult {
  label: "BENIGN" | "MALICIOUS";
  score: number;
  logits: { benign: number; malicious: number };
  latency_ms: number;
  blocked: number;
  policy: string;
  threshold: number;
  error?: string;
}

export interface PromptGuardBothResult {
  input: PromptGuardResult;
  output: PromptGuardResult;
  would_block: boolean;
}

export async function guardClassify(
  env: Env,
  text: string,
  opts: {
    probe_id?: string;
    phase?: "input" | "output";
    threshold?: number;
    policy?: "block" | "log" | "pass";
  } = {},
): Promise<PromptGuardResult> {
  if (!env.PROMPT_GUARD) {
    return fallback("PROMPT_GUARD binding not available", opts);
  }

  try {
    const res = await env.PROMPT_GUARD.fetch(
      new Request("https://prompt-guard/classify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          probe_id: opts.probe_id,
          phase: opts.phase ?? "input",
          threshold: opts.threshold ?? 0.5,
          policy: opts.policy ?? "log",
        }),
      }),
    );

    if (!res.ok) {
      return fallback(`Guard returned ${res.status}`, opts);
    }

    return (await res.json()) as PromptGuardResult;
  } catch (err) {
    return fallback(err instanceof Error ? err.message : String(err), opts);
  }
}

export async function guardClassifyBoth(
  env: Env,
  inputText: string,
  outputText: string,
  opts: {
    probe_id?: string;
    threshold?: number;
    policy?: "block" | "log" | "pass";
  } = {},
): Promise<PromptGuardBothResult> {
  if (!env.PROMPT_GUARD) {
    const fb = fallback("PROMPT_GUARD binding not available", opts);
    return { input: fb, output: fb, would_block: false };
  }

  try {
    const res = await env.PROMPT_GUARD.fetch(
      new Request("https://prompt-guard/classify-both", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          input_text: inputText,
          output_text: outputText,
          probe_id: opts.probe_id,
          threshold: opts.threshold ?? 0.5,
          policy: opts.policy ?? "log",
        }),
      }),
    );

    if (!res.ok) {
      const both = fallback(`Guard returned ${res.status}`, opts);
      return { input: both, output: both, would_block: false };
    }

    return (await res.json()) as PromptGuardBothResult;
  } catch (err) {
    const both = fallback(err instanceof Error ? err.message : String(err), opts);
    return { input: both, output: both, would_block: false };
  }
}

export async function guardReport(
  env: Env,
  probeId?: string,
): Promise<unknown> {
  if (!env.PROMPT_GUARD) return { error: "no binding" };

  const url = probeId
    ? `https://prompt-guard/report?probe_id=${encodeURIComponent(probeId)}`
    : "https://prompt-guard/report";

  const res = await env.PROMPT_GUARD.fetch(new Request(url));
  return res.json();
}

function fallback(
  error: string,
  opts: { threshold?: number; policy?: "block" | "log" | "pass" },
): PromptGuardResult {
  return {
    label: "BENIGN",
    score: 0,
    logits: { benign: 0, malicious: 0 },
    latency_ms: 0,
    blocked: 0,
    policy: opts.policy ?? "log",
    threshold: opts.threshold ?? 0.5,
    error,
  };
}
