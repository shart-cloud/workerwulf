import type { ProbeResult, Track } from "@wulf/shared";
import { WorkerEntrypoint } from "cloudflare:workers";
import type { WorkerLoader } from "./loader.js";
import type { AiAgentRunParams } from "./agent.js";
import { probes } from "./probes/index.js";

export interface Env {
  AI: Ai;
  LOADER: WorkerLoader;
  PREY_KV: KVNamespace;
  PREY_R2: R2Bucket;
  LOGPUSH_R2: R2Bucket;
  PREY_D1: D1Database;
  PREY_DO: DurableObjectNamespace;
  PREY_DO_SECURE: DurableObjectNamespace;
  PROMPT_GUARD?: Fetcher;
  LLAMAFIREWALL?: Fetcher;
  WULF_CALLBACK_HTTP_BASE?: string;
  WULF_DNS_EXFIL_ZONE?: string;
  [key: string]: unknown;
}

export interface AiAgentRequest {
  run_id?: string;
  prompt_tier?: "naive" | "basic" | "hardened" | "defense";
  global_outbound?: "open" | "null";
  model?: string;
  conversation_id?: string;
  turn?: number;
  params?: Record<string, unknown>;
}

export class AiPlayApi extends WorkerEntrypoint<Env> {
  async execSql(args: { name?: string; cmd?: string; input?: string }): Promise<unknown> {
    const id = this.env.PREY_DO.idFromName(args.name ?? "ai-test");
    const stub = this.env.PREY_DO.get(id);
    const path = `/${args.cmd ?? "classic-sqli"}`;
    const query = args.input ? `?input=${encodeURIComponent(args.input)}` : "";
    const res = await stub.fetch(new Request(`http://do${path}${query}`));
    const body = (await res.json()) as { ok?: boolean; data?: unknown; error?: string };
    if (!res.ok || body.ok === false) {
      throw new Error(body.error ?? `DO request failed with ${res.status}`);
    }
    return body.data;
  }

  async stubEnum(): Promise<unknown> {
    const stub = this.env.PREY_DO.get(this.env.PREY_DO.idFromName("enum-test"));
    const methods: string[] = [];
    let proto: object | null = Object.getPrototypeOf(stub);
    while (proto && proto !== Object.prototype) {
      for (const method of Object.getOwnPropertyNames(proto)) {
        if (method === "constructor") continue;
        const desc = Object.getOwnPropertyDescriptor(proto, method);
        if (desc && typeof desc.value === "function" && !methods.includes(method)) {
          methods.push(method);
        }
      }
      proto = Object.getPrototypeOf(proto);
    }
    return { binding: "PREY_DO", stub_methods: methods.sort() };
  }
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/" || url.pathname === "/probes") {
      return json({ probes: Object.keys(probes) });
    }

    if (url.pathname === "/agent") {
      return handleAgent(req, env, ctx);
    }

    const match = url.pathname.match(/^\/probe\/([A-Z0-9-]+)$/);
    if (!match) return json({ error: "not_found" }, 404);

    const testId = match[1]!;
    const probe = probes[testId];
    if (!probe) return json({ error: "unknown_test_id", test_id: testId }, 404);

    const runId = url.searchParams.get("run_id") ?? crypto.randomUUID();

    try {
      const result = await probe({ env, ctx, req, runId });
      return json(result satisfies ProbeResult);
    } catch (err) {
      return json(
        {
          test_id: testId,
          error: "probe_threw",
          message: err instanceof Error ? err.message : String(err),
          stack: err instanceof Error ? err.stack : undefined,
        },
        500,
      );
    }
  },
};

async function handleAgent(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  let body: AiAgentRequest = {};
  try {
    if (req.method === "POST") body = (await req.json()) as AiAgentRequest;
  } catch {
    body = {};
  }

  const runId = body.run_id ?? url.searchParams.get("run_id") ?? crypto.randomUUID();
  const promptTier = (body.prompt_tier ?? url.searchParams.get("prompt_tier") ?? "naive") as AiAgentRunParams["promptTier"];
  const globalOutbound = (body.global_outbound ?? url.searchParams.get("global_outbound") ?? "null") as AiAgentRunParams["globalOutbound"];
  const model = body.model ?? url.searchParams.get("model") ?? "@cf/meta/llama-3.1-8b-instruct";
  const conversationId = body.conversation_id ?? url.searchParams.get("conversation_id") ?? runId;
  const turn = body.turn ?? parseInt(url.searchParams.get("turn") ?? "1", 10);
  const params = body.params ?? {};

  const task = params.task as string | undefined;
  if (!task && !params.conversation_history) {
    return json({ error: "missing_params", message: "provide task or conversation_history in params" }, 400);
  }

  const { runAiAgent } = await import("./agent.js");
  try {
    const result = await runAiAgent(env, {
      task,
      model,
      promptTier,
      globalOutbound,
      conversationId,
      turn,
      params,
    });
    return json(result);
  } catch (err) {
    return json(
      {
        error: "agent_error",
        message: err instanceof Error ? err.message : String(err),
      },
      500,
    );
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}