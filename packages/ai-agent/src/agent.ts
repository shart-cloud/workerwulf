import type { Env } from "./index.js";
import type { WorkerCode, WorkerStub } from "./loader.js";
import { buildSystemPrompt, buildMessages, TYPE_DECLARATIONS } from "./prompts.js";
import { validateGeneratedCode, type ValidatorMode } from "./validator.js";
import { buildEgressFetcher, parseAllowlist } from "./egress.js";
import {
  lfScanInput,
  lfScanOutput,
  lfScanTrace,
  type LlamaFirewallScanResult,
} from "./llamafirewall.js";

const CHILD_COMPAT_DATE = "2026-05-01";

export type GatePolicy = "block" | "log" | "pass";

export interface GuardOptions {
  scanInput?: GatePolicy;     // default: "pass"
  scanOutput?: GatePolicy;    // default: "pass"
  scanTrace?: GatePolicy;     // default: "pass" (post-execution, never blocks the pipeline)
  astValidator?: boolean;     // default: only true for "defense" tier
  validatorMode?: ValidatorMode; // which code validator to run when enabled. default: "ast"
  probeId?: string;           // optional tag for LlamaFirewall SQLite logs
}

export interface AiAgentRunParams {
  task?: string;
  model: string;
  promptTier: "naive" | "basic" | "hardened" | "defense";
  globalOutbound: "open" | "null" | "allowlist";
  conversationId: string;
  turn: number;
  params: Record<string, unknown>;
  guard?: GuardOptions;
}

export type GateAction = "blocked" | "allowed" | "skipped" | "flagged";

export interface GuardStageResult extends LlamaFirewallScanResult {
  gate_action: GateAction;
}

export interface GuardResults {
  scan_input?: GuardStageResult;
  scan_output?: GuardStageResult;
  scan_trace?: GuardStageResult;
  pipeline_blocked: boolean;
  blocked_at?: "scan_input" | "scan_output" | "ast_validator";
  total_guard_latency_ms: number;
}

export interface AiAgentRunResult {
  run_id: string;
  conversation_id: string;
  turn: number;
  model: string;
  prompt_tier: string;
  global_outbound: string;
  task?: string;
  generated_code: string;
  code_length: number;
  code_contains_fetch: boolean;
  code_contains_eval: boolean;
  code_contains_new_function: boolean;
  code_contains_import: boolean;
  code_contains_global_this: boolean;
  code_contains_object_prototype: boolean;
  validator_rejected: boolean;
  validator_reasons: string[];
  validator_mode?: ValidatorMode;
  sandbox_result?: unknown;
  sandbox_error?: string;
  ai_metadata?: Record<string, unknown>;
  guard_results?: GuardResults;
}

const conversationStore = new Map<string, { role: "user" | "assistant"; content: string }[]>();

const CHILD_WRAPPER_PREFIX = `export default {
  async fetch(req, env, ctx) {
`;

const CHILD_WRAPPER_SUFFIX = `
  }
};`;

const EMPTY_CODE_ANALYSIS = {
  code_contains_fetch: false,
  code_contains_eval: false,
  code_contains_new_function: false,
  code_contains_import: false,
  code_contains_global_this: false,
  code_contains_object_prototype: false,
};

export async function runAiAgent(env: Env, params: AiAgentRunParams): Promise<AiAgentRunResult> {
  const systemPrompt = buildSystemPrompt(params.promptTier, TYPE_DECLARATIONS);

  const task = params.task ?? "";
  const history = conversationStore.get(params.conversationId);

  const messages = buildMessages(systemPrompt, task, history);

  const guard = params.guard ?? {};
  const inputPolicy = guard.scanInput ?? "pass";
  const outputPolicy = guard.scanOutput ?? "pass";
  const tracePolicy = guard.scanTrace ?? "pass";
  // AST validator default mirrors prior behavior: only on "defense" tier unless explicitly overridden.
  const astEnabled = guard.astValidator ?? (params.promptTier === "defense");
  const validatorMode: ValidatorMode = guard.validatorMode ?? "ast";

  const guardResults: GuardResults = {
    pipeline_blocked: false,
    total_guard_latency_ms: 0,
  };

  // ── Gate 1: scan-input ──────────────────────────────────────────────────
  if (inputPolicy !== "pass" && task) {
    const inputScan = await lfScanInput(env, task, guard.probeId, inputPolicy);
    guardResults.total_guard_latency_ms += inputScan.latency_ms;
    const action: GateAction =
      inputPolicy === "block" && inputScan.decision === "block" ? "blocked" : "allowed";
    guardResults.scan_input = { ...inputScan, gate_action: action };
    if (action === "blocked") {
      guardResults.pipeline_blocked = true;
      guardResults.blocked_at = "scan_input";
      return buildBlockedResult(params, task, "", guardResults, "blocked by scan-input gate");
    }
  } else if (inputPolicy === "pass") {
    // Don't record anything for skipped stages — keeps the result lean.
  }

  // ── Code generation ────────────────────────────────────────────────────
  const aiResult = await env.AI.run(params.model as any, {
    messages: messages as any,
    stream: false,
  });

  const generatedCode = extractCodeFromAiResponse(aiResult);
  const codeAnalysis = analyzeGeneratedCode(generatedCode);

  // ── Gate 2: scan-output ────────────────────────────────────────────────
  if (outputPolicy !== "pass" && generatedCode) {
    const outputScan = await lfScanOutput(env, generatedCode, guard.probeId, outputPolicy);
    guardResults.total_guard_latency_ms += outputScan.latency_ms;
    const action: GateAction =
      outputPolicy === "block" && outputScan.decision === "block" ? "blocked" : "allowed";
    guardResults.scan_output = { ...outputScan, gate_action: action };
    if (action === "blocked") {
      guardResults.pipeline_blocked = true;
      guardResults.blocked_at = "scan_output";
      return buildBlockedResult(params, task, generatedCode, guardResults, "blocked by scan-output gate", codeAnalysis, aiResult);
    }
  }

  // ── Gate 3: AST validator ──────────────────────────────────────────────
  const validation = astEnabled
    ? validateGeneratedCode(generatedCode, validatorMode)
    : { passed: true, rejected: false, reasons: [] as string[], mode: undefined };

  if (validation.rejected) {
    guardResults.pipeline_blocked = true;
    guardResults.blocked_at = "ast_validator";
    return buildBlockedResult(
      params, task, generatedCode, guardResults, "code rejected by validation",
      codeAnalysis, aiResult, validation.reasons, validation.mode,
    );
  }

  // ── Sandbox execution ──────────────────────────────────────────────────
  const executableCode = hasDefaultExport(generatedCode)
    ? generatedCode
    : CHILD_WRAPPER_PREFIX + "\n" + generatedCode + "\n" + CHILD_WRAPPER_SUFFIX;

  const result: AiAgentRunResult = {
    run_id: params.conversationId,
    conversation_id: params.conversationId,
    turn: params.turn,
    model: params.model,
    prompt_tier: params.promptTier,
    global_outbound: params.globalOutbound,
    task,
    generated_code: generatedCode,
    code_length: generatedCode.length,
    ...codeAnalysis,
    validator_rejected: validation.rejected,
    validator_reasons: validation.reasons,
    validator_mode: astEnabled ? validatorMode : undefined,
    ai_metadata: extractAiMetadata(aiResult),
  };

  try {
    const sandboxResult = await executeInSandbox(env, executableCode, params);
    result.sandbox_result = sandboxResult;
  } catch (err) {
    result.sandbox_error = err instanceof Error ? err.message : String(err);
  }

  // ── Gate 4: scan-trace (post-execution; never blocks the pipeline) ─────
  if (tracePolicy !== "pass" && task && generatedCode) {
    const traceScan = await lfScanTrace(
      env,
      [
        { role: "user", content: task },
        { role: "assistant", content: generatedCode },
      ],
      guard.probeId,
      tracePolicy,
    );
    guardResults.total_guard_latency_ms += traceScan.latency_ms;
    const action: GateAction =
      tracePolicy === "block" && traceScan.decision === "block" ? "flagged" : "allowed";
    guardResults.scan_trace = { ...traceScan, gate_action: action };
    // Note: scan-trace is post-execution, so "flagged" here means "future turns should be reviewed".
    // The current turn's sandbox result has already been computed.
  }

  if (history) {
    history.push({ role: "user", content: task });
    history.push({ role: "assistant", content: generatedCode });
  } else if (params.turn === 1) {
    conversationStore.set(params.conversationId, [
      { role: "user", content: task },
      { role: "assistant", content: generatedCode },
    ]);
  }

  if (anyGateActive(guard)) {
    result.guard_results = guardResults;
  }

  return result;
}

function anyGateActive(guard: GuardOptions): boolean {
  return (
    (guard.scanInput && guard.scanInput !== "pass") ||
    (guard.scanOutput && guard.scanOutput !== "pass") ||
    (guard.scanTrace && guard.scanTrace !== "pass") ||
    guard.astValidator === true
  );
}

function buildBlockedResult(
  params: AiAgentRunParams,
  task: string,
  generatedCode: string,
  guardResults: GuardResults,
  sandboxError: string,
  codeAnalysis: typeof EMPTY_CODE_ANALYSIS = EMPTY_CODE_ANALYSIS,
  aiResult?: unknown,
  validatorReasons: string[] = [],
  validatorMode?: ValidatorMode,
): AiAgentRunResult {
  return {
    run_id: params.conversationId,
    conversation_id: params.conversationId,
    turn: params.turn,
    model: params.model,
    prompt_tier: params.promptTier,
    global_outbound: params.globalOutbound,
    task,
    generated_code: generatedCode,
    code_length: generatedCode.length,
    ...codeAnalysis,
    validator_rejected: guardResults.blocked_at === "ast_validator",
    validator_reasons: validatorReasons,
    validator_mode: validatorMode,
    sandbox_error: sandboxError,
    ai_metadata: aiResult ? extractAiMetadata(aiResult) : undefined,
    guard_results: guardResults,
  };
}

function extractCodeFromAiResponse(aiResult: unknown): string {
  let text = "";

  if (aiResult && typeof aiResult === "object") {
    const r = aiResult as Record<string, unknown>;
    if (typeof r.response === "string") {
      text = r.response;
    } else if (r.choices && Array.isArray(r.choices) && r.choices.length > 0) {
      const choice = r.choices[0] as Record<string, unknown>;
      if (choice.message && typeof choice.message === "object") {
        const msg = choice.message as Record<string, unknown>;
        text = String(msg.content ?? "");
      } else if (typeof choice.text === "string") {
        text = choice.text;
      }
    }
  } else if (typeof aiResult === "string") {
    text = aiResult;
  }

  const codeBlockMatch = text.match(/```(?:typescript|javascript|ts|js)?\s*([\s\S]*?)```/);
  if (codeBlockMatch && codeBlockMatch[1]) {
    return codeBlockMatch[1].trim();
  }

  const exportMatch = text.match(/(export\s+(?:default\s+)?.*)/);
  if (exportMatch) {
    const idx = text.indexOf(exportMatch[0]);
    return text.slice(idx).trim();
  }

  return text.trim();
}

function analyzeGeneratedCode(code: string) {
  return {
    // The naive `\bfetch\s*\(` matched the Worker handler signature
    // (`async fetch(request, env, ctx)`), false-positiving every Worker. Exclude
    // `async\s+fetch(` via negative lookbehind so we only count real call sites.
    code_contains_fetch: /(?<!async\s+)\bfetch\s*\(/i.test(code),
    code_contains_eval: /\beval\s*\(/i.test(code),
    code_contains_new_function: /\bnew\s+Function\s*\(/i.test(code),
    code_contains_import: /\bimport\s*\(/i.test(code),
    code_contains_global_this: /\bglobalThis\b/i.test(code),
    code_contains_object_prototype: /\bObject\.prototype\b/i.test(code),
  };
}

function hasDefaultExport(code: string): boolean {
  return /\bexport\s+default\b/.test(code);
}

function extractAiMetadata(aiResult: unknown): Record<string, unknown> {
  const meta: Record<string, unknown> = {};
  if (aiResult && typeof aiResult === "object") {
    const r = aiResult as Record<string, unknown>;
    for (const key of ["usage", "model", "stop_reason", "stop"]) {
      if (key in r) meta[key] = r[key];
    }
  }
  return meta;
}

async function executeInSandbox(
  env: Env,
  code: string,
  params: AiAgentRunParams,
): Promise<unknown> {
  const bindings: Record<string, unknown> = {
    WULF_CALLBACK_HTTP_BASE: env.WULF_CALLBACK_HTTP_BASE,
  };

  // Resolve the child's egress posture:
  //   "null"      → null      (platform blocks every outbound subrequest)
  //   "allowlist" → Fetcher   (subrequests routed through the egress proxy; §7 item 1)
  //   "open"      → undefined  (inherit the loader's default = open internet)
  let globalOutbound: Fetcher | null | undefined;
  if (params.globalOutbound === "null") {
    globalOutbound = null;
  } else if (params.globalOutbound === "allowlist") {
    globalOutbound = buildEgressFetcher(env.LOADER, parseAllowlist(env.WULF_EGRESS_ALLOWLIST));
  } else {
    globalOutbound = undefined;
  }

  const codeObj: WorkerCode = {
    compatibilityDate: CHILD_COMPAT_DATE,
    mainModule: "index.js",
    modules: { "index.js": code },
    env: bindings,
    globalOutbound,
  };

  const stub: WorkerStub = env.LOADER.load(codeObj);
  const fetcher = stub.getEntrypoint();

  const res = await fetcher.fetch(new Request("https://wulf-ai-child.invalid/"));
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = await res.text();
  }

  return {
    status: res.status,
    ok: res.ok,
    headers: Object.fromEntries(res.headers.entries()),
    body,
  };
}

export function getConversationHistory(conversationId: string): { role: string; content: string }[] | undefined {
  return conversationStore.get(conversationId);
}

export function clearConversation(conversationId: string): void {
  conversationStore.delete(conversationId);
}
