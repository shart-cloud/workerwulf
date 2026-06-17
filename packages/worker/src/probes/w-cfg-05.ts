import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-CFG-05 — nodejs_compat attack-surface enumeration (misconfig).
 *
 * Enabling the `nodejs_compat` compatibility flag injects a swathe of Node.js
 * globals (`Buffer`, `process`, `global`, `setImmediate`, …) and, notably,
 * populates `process.env` from the Worker's text bindings — a second path that
 * surfaces config/secret vars. Operators routinely enable the flag they don't
 * need, silently widening the isolate's attack surface. This probe enumerates
 * what the flag exposed; run it against both the default deploy and the
 * `wrangler.no-compat.toml` variant and diff the two to quantify the delta.
 */
export const wCfg05: Probe = async ({ env, runId }) => {
  const g = globalThis as Record<string, unknown>;
  const has = (n: string) => typeof g[n] !== "undefined";

  const injected = {
    Buffer: has("Buffer"),
    process: has("process"),
    global: has("global"),
    setImmediate: has("setImmediate"),
    clearImmediate: has("clearImmediate"),
  };

  let bufferWorks = false;
  try {
    const bufferCtor = g["Buffer"] as
      | { from?: (s: string) => { toString: (enc: string) => string } }
      | undefined;
    bufferWorks =
      !!bufferCtor?.from &&
      bufferCtor.from("wulf").toString("hex") === "77756c66";
  } catch {
    bufferWorks = false;
  }

  const proc = g["process"] as
    | { version?: string; platform?: string; env?: Record<string, string> }
    | undefined;
  const procEnv = proc?.env ?? null;
  const procEnvKeys = procEnv ? Object.keys(procEnv) : [];
  const wulfVarsViaProcessEnv = procEnvKeys.filter((k) => k.startsWith("WULF_"));
  // Concrete demonstration: does the [vars] value also leak through process.env?
  const varSurfaced =
    !!procEnv &&
    !!env.WULF_ENV_PROBE &&
    procEnv["WULF_ENV_PROBE"] === env.WULF_ENV_PROBE;

  const compatOn = injected.process || injected.Buffer;
  const surfacesConfig = wulfVarsViaProcessEnv.length > 0;

  return base({
    test_id: "W-CFG-05",
    track: "worker",
    description:
      "nodejs_compat attack-surface enumeration — injected Node globals and process.env config exposure",
    result: compatOn ? "accessible" : "blocked",
    severity: surfacesConfig ? "medium" : compatOn ? "low" : "informational",
    run_id: runId,
    tags: ["misconfig", "misconfig:compat"],
    details: {
      nodejs_compat_detected: compatOn,
      injected_globals: injected,
      buffer_functional: bufferWorks,
      process_version: proc?.version ?? null,
      process_platform: proc?.platform ?? null,
      process_env_key_count: procEnvKeys.length,
      wulf_vars_via_process_env: wulfVarsViaProcessEnv,
      vars_surfaced_through_process_env: varSurfaced,
      note: compatOn
        ? "nodejs_compat is ON: Node globals are injected and process.env mirrors text bindings — a wider surface than the bare isolate. Compare against the wrangler.no-compat.toml deploy."
        : "nodejs_compat is OFF: none of the Node globals are present — the minimal-surface baseline.",
    },
    comparison: {
      aws_lambda:
        "accessible — full Node.js runtime (process, fs, net, child_process) always present",
      azure_functions: "accessible — full Node.js runtime",
      gcp_functions: "accessible — full Node.js runtime",
    },
  });
};
