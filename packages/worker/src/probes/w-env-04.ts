import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wEnv04: Probe = async ({ runId }) => {
  const nav = (globalThis as { navigator?: Record<string, unknown> }).navigator;
  const wasmFeatures: Record<string, boolean> = {};

  for (const [name, bytes] of Object.entries(WASM_FEATURE_PROBES)) {
    try {
      wasmFeatures[name] = await WebAssembly.validate(bytes);
    } catch {
      wasmFeatures[name] = false;
    }
  }

  return base({
    test_id: "W-ENV-04",
    track: "worker",
    description: "V8 / runtime version and feature flags",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      navigator: nav
        ? {
            userAgent: nav.userAgent ?? null,
            language: nav.language ?? null,
            platform: nav.platform ?? null,
          }
        : null,
      es_feature_probes: {
        BigInt: typeof BigInt !== "undefined",
        WeakRef: typeof WeakRef !== "undefined",
        FinalizationRegistry: typeof FinalizationRegistry !== "undefined",
        AggregateError: typeof AggregateError !== "undefined",
        Error_cause: (() => {
          try {
            return "cause" in new Error("x", { cause: "y" });
          } catch {
            return false;
          }
        })(),
        Array_groupBy: typeof (Array as unknown as { groupBy?: unknown }).groupBy === "function",
        Object_hasOwn: typeof Object.hasOwn === "function",
        Promise_withResolvers: typeof (Promise as unknown as { withResolvers?: unknown }).withResolvers === "function",
        Iterator_helpers: typeof (globalThis as unknown as { Iterator?: unknown }).Iterator !== "undefined",
      },
      wasm_features: wasmFeatures,
    },
  });
};

// Minimal Wasm modules that exercise a single proposal each.
// If WebAssembly.validate returns true, the feature is supported.
const WASM_FEATURE_PROBES: Record<string, Uint8Array> = {
  baseline_v1: new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]),
};
