import type { Env } from "./index.js";

export const LLAMA_GUARD_MODEL = "@cf/meta/llama-guard-3-8b";

/**
 * Llama Guard 3 safety categories (MLCommons taxonomy).
 * Guard returns "unsafe\nS{N}" when content violates category N.
 * S14 ("Code Interpreter Abuse") is the relevant category for code-gen injection.
 */
export const GUARD_CATEGORIES: Record<string, string> = {
  S1: "Violent Crimes",
  S2: "Non-Violent Crimes",
  S3: "Sex-Related Crimes",
  S4: "Child Sexual Exploitation",
  S5: "Defamation",
  S6: "Specialized Advice",
  S7: "Privacy",
  S8: "Intellectual Property",
  S9: "Indiscriminate Weapons",
  S10: "Hate",
  S11: "Suicide & Self-Harm",
  S12: "Sexual Content",
  S13: "Elections",
  S14: "Code Interpreter Abuse",
};

export interface Llg3Result {
  raw_response: string;
  safe: boolean;
  categories_violated: string[];
  category_labels: string[];
  s14_triggered: boolean;
  latency_ms: number;
  error?: string;
}

export async function llg3ClassifyInput(env: Env, task: string): Promise<Llg3Result> {
  return runLlg3(env, [{ role: "user", content: task }]);
}

export async function llg3ClassifyOutput(
  env: Env,
  task: string,
  generatedCode: string,
): Promise<Llg3Result> {
  return runLlg3(env, [
    { role: "user", content: task },
    { role: "assistant", content: generatedCode },
  ]);
}

export async function llg3ClassifyBoth(
  env: Env,
  task: string,
  generatedCode: string,
): Promise<{ input: Llg3Result; output: Llg3Result }> {
  const [input, output] = await Promise.all([
    llg3ClassifyInput(env, task),
    llg3ClassifyOutput(env, task, generatedCode),
  ]);
  return { input, output };
}

async function runLlg3(
  env: Env,
  messages: { role: string; content: string }[],
): Promise<Llg3Result> {
  const t0 = Date.now();
  try {
    const aiResult = await env.AI.run(LLAMA_GUARD_MODEL as any, {
      messages: messages as any,
      max_tokens: 32,
    });
    const latency_ms = Date.now() - t0;
    const raw = extractText(aiResult);
    return parseGuardResponse(raw, latency_ms);
  } catch (err) {
    return {
      raw_response: "",
      safe: true,
      categories_violated: [],
      category_labels: [],
      s14_triggered: false,
      latency_ms: Date.now() - t0,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function extractText(aiResult: unknown): string {
  if (typeof aiResult === "string") return aiResult;
  if (aiResult && typeof aiResult === "object") {
    const r = aiResult as Record<string, unknown>;
    if (typeof r.response === "string") return r.response;
    if (r.choices && Array.isArray(r.choices) && r.choices.length > 0) {
      const choice = r.choices[0] as Record<string, unknown>;
      if (choice.message && typeof choice.message === "object") {
        return String((choice.message as Record<string, unknown>).content ?? "");
      }
    }
  }
  return String(aiResult);
}

function parseGuardResponse(raw: string, latency_ms: number): Llg3Result {
  const trimmed = raw.trim().toLowerCase();

  if (trimmed === "safe" || trimmed.startsWith("safe")) {
    return {
      raw_response: raw.trim(),
      safe: true,
      categories_violated: [],
      category_labels: [],
      s14_triggered: false,
      latency_ms,
    };
  }

  const categories_violated: string[] = [];
  const lines = raw.trim().split("\n");
  for (const line of lines.slice(1)) {
    const matches = line.match(/S\d+/g);
    if (matches) categories_violated.push(...matches);
  }

  return {
    raw_response: raw.trim(),
    safe: false,
    categories_violated,
    category_labels: categories_violated.map((c) => GUARD_CATEGORIES[c] ?? `Unknown(${c})`),
    s14_triggered: categories_violated.includes("S14"),
    latency_ms,
  };
}
