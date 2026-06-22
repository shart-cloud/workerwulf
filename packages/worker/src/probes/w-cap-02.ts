import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-CAP-02 — Secrets Store capability-binding blast radius (misconfig).
 *
 * The most literal Serverless-Prey analog on Cloudflare: a Secrets Store binding
 * hands the Worker the *plaintext secret value* via `env.SECRET.get()`. Any code
 * that runs in the isolate — including injected/generated Track 4 code — reads it
 * straight off the binding, exactly like lifting a credential out of a Lambda's
 * environment. Where `W-CAP-01` (Hyperdrive) leaks DB creds and `W-BND-*`
 * enumerate bindings, this exercises the purest "creds in the env" capability.
 * This probe resolves the bound secret and reports whether it retrieved a value
 * — redacting all but a short prefix; the canary match is an exact substring.
 *
 * Deploy-only: requires the live SECRET binding + a store entry. Locally → blocked.
 */
export const wCap02: Probe = async ({ env, runId }) => {
  const secret = env.SECRET;
  if (!secret) {
    return base({
      test_id: "W-CAP-02",
      track: "worker",
      description:
        "Secrets Store capability binding — read the plaintext secret value straight off env.SECRET.get()",
      target: "env.SECRET",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: { error: "SECRET binding not present (expected locally / pre-deploy)" },
    });
  }

  let retrieved = false;
  let length: number | null = null;
  let preview: string | null = null;
  let isCanary = false;
  let error: string | null = null;

  try {
    const value = await secret.get();
    retrieved = typeof value === "string" && value.length > 0;
    length = typeof value === "string" ? value.length : null;
    // Posture: never emit the full secret (cf. F-004). Prefix only; canary match
    // is an exact substring so a planted canary still proves exfil.
    preview = retrieved ? `${value.slice(0, 6)}…(${length} chars, redacted)` : null;
    isCanary = retrieved && value.includes("flag{w-cap-02");
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return base({
    test_id: "W-CAP-02",
    track: "worker",
    description:
      "Secrets Store capability binding — read the plaintext secret value straight off env.SECRET.get()",
    target: "env.SECRET",
    result: retrieved ? "accessible" : error ? "error" : "partial",
    severity: retrieved ? "critical" : "high",
    run_id: runId,
    tags: ["misconfig", "misconfig:binding"],
    details: {
      secret_retrieved: retrieved,
      is_canary: isCanary,
      value_length: length,
      value_preview: preview,
      error,
      note: "A Secrets Store binding returns the plaintext secret to any code in the isolate via .get(). Generated/injected code (Track 4) with this binding reads the credential directly — the cleanest Cloudflare analog to Serverless Prey's central finding.",
    },
    comparison: {
      aws_lambda:
        "accessible — equivalent to a Secrets Manager / Parameter Store value fetched with the function role, or a plaintext env var",
      azure_functions: "accessible — Key Vault reference resolved into app settings",
      gcp_functions: "accessible — Secret Manager value mounted/fetched with the runtime SA",
    },
  });
};
