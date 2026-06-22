import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

// Cheap, widely-available text model; max_tokens kept tiny — the capability is
// proven by a single successful inference, not by burning quota.
const MODEL = "@cf/meta/llama-3.2-3b-instruct";

/**
 * W-CAP-09 — Workers AI capability-binding blast radius (misconfig / financial DoS).
 *
 * An `[ai]` binding lets *any* code in the isolate — including injected/generated
 * Track 4 code — run arbitrary Workers AI models at the account's expense via
 * `env.AI.run()`. No per-call authz, no model allowlist, no spend cap at the
 * binding. That is the unmetered-inference / financial-DoS primitive the threat
 * model lists as **unmitigated** ("Workers AI quota exhaustion"), plus free
 * arbitrary model execution (run a large model in a loop, or a model the operator
 * never intended to expose). This probe runs one tiny canary completion to prove
 * the binding executes inference, then reports the model and a response snippet.
 *
 * Deploy-only: requires the live AI binding. Locally → blocked.
 */
export const wCap09: Probe = async ({ env, runId }) => {
  const ai = env.AI;
  if (!ai) {
    return base({
      test_id: "W-CAP-09",
      track: "worker",
      description:
        "Workers AI capability binding — run arbitrary models at the account's expense via env.AI.run() (unmetered inference / financial DoS)",
      target: "env.AI",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: { error: "AI binding not present (expected locally / pre-deploy)" },
    });
  }

  let ran = false;
  let responsePreview: string | null = null;
  let error: string | null = null;

  try {
    const out: any = await ai.run(MODEL as any, {
      messages: [{ role: "user", content: "Reply with exactly: w-cap-09-ai-canary" }],
      max_tokens: 16,
      stream: false,
    } as any);
    const text =
      typeof out === "string" ? out : (out?.response ?? JSON.stringify(out));
    responsePreview = String(text).slice(0, 256);
    ran = true;
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return base({
    test_id: "W-CAP-09",
    track: "worker",
    description:
      "Workers AI capability binding — run arbitrary models at the account's expense via env.AI.run() (unmetered inference / financial DoS)",
    target: "env.AI",
    result: ran ? "accessible" : error ? "error" : "partial",
    severity: ran ? "high" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:binding"],
    details: {
      inference_ran: ran,
      model: MODEL,
      response_preview: responsePreview,
      error,
      note: "An AI binding is uncapped, unauthenticated inference at the account's expense for any code in the isolate. Injected code (Track 4) can run a large model in a loop (financial DoS — the threat model's unmitigated 'Workers AI quota exhaustion' line) or invoke models the operator never meant to expose.",
    },
    comparison: {
      aws_lambda:
        "accessible — analog to bedrock:InvokeModel granted to the function role, billed to the account",
      azure_functions: "accessible — Azure OpenAI key/endpoint in app settings",
      gcp_functions: "accessible — aiplatform.endpoints.predict on the runtime service account",
    },
  });
};
