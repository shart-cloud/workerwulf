import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../index.js";
import type { AiAgentRunParams, AiAgentRunResult } from "../agent.js";

export function now(): string {
  return new Date().toISOString();
}

export function base(p: Omit<ProbeResult, "timestamp">): ProbeResult {
  return { timestamp: now(), ...p };
}

export interface AgentProbeCtx {
  env: Env;
  ctx: ExecutionContext;
  req: Request;
  runId: string;
}

export type AgentProbe = (c: AgentProbeCtx) => Promise<ProbeResult>;

export async function runAgent(
  env: Env,
  runId: string,
  overrides: Partial<AiAgentRunParams>,
): Promise<AiAgentRunResult> {
  const { runAiAgent } = await import("../agent.js");
  const globalOutbound = (overrides.globalOutbound ?? "null") as "open" | "null";
  const promptTier = (overrides.promptTier ?? "naive") as AiAgentRunParams["promptTier"];
  const model = overrides.model ?? "@cf/meta/llama-3.1-8b-instruct";

  return runAiAgent(env, {
    task: overrides.task ?? "",
    model,
    promptTier,
    globalOutbound,
    conversationId: runId,
    turn: overrides.turn ?? 1,
    params: overrides.params ?? {},
    guard: overrides.guard,
  });
}

export function chatAgent(
  env: Env,
  runId: string,
  baseOverrides: Partial<AiAgentRunParams>,
): {
  sendTurn: (task: string, turn: number) => Promise<AiAgentRunResult>;
} {
  return {
    sendTurn: async (task: string, turn: number) => {
      const { runAiAgent } = await import("../agent.js");
      return runAiAgent(env, {
        task,
        model: baseOverrides.model ?? "@cf/meta/llama-3.1-8b-instruct",
        promptTier: (baseOverrides.promptTier ?? "naive") as AiAgentRunParams["promptTier"],
        globalOutbound: (baseOverrides.globalOutbound ?? "null") as "open" | "null",
        conversationId: runId,
        turn,
        params: baseOverrides.params ?? {},
      });
    },
  };
}

export async function queryCallbackd(
  callbackBase: string | undefined,
  path: string,
): Promise<{ found: boolean; events: unknown[] }> {
  if (!callbackBase) return { found: false, events: [] };
  try {
    const res = await fetch(`${callbackBase}/check?path=${encodeURIComponent(path)}`);
    if (!res.ok) return { found: false, events: [] };
    return (await res.json()) as { found: boolean; events: unknown[] };
  } catch {
    return { found: false, events: [] };
  }
}

export function makeCallbackUrl(base: string | undefined, path: string): string | undefined {
  if (!base) return undefined;
  return `${base.replace(/\/+$/, "")}${path}`;
}
