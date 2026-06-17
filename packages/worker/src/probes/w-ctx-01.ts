import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wCtx01: Probe = async ({ ctx, runId }) => {
  const own_keys: string[] = [];
  for (const k of Object.getOwnPropertyNames(ctx)) own_keys.push(k);

  const own_symbols = Object.getOwnPropertySymbols(ctx).map((s) => s.toString());

  const proto_chain: Array<{
    constructor: string | null;
    keys: string[];
  }> = [];
  let p: object | null = Object.getPrototypeOf(ctx);
  let depth = 0;
  while (p && p !== Object.prototype && depth < 8) {
    proto_chain.push({
      constructor: p.constructor?.name ?? null,
      keys: Object.getOwnPropertyNames(p),
    });
    p = Object.getPrototypeOf(p);
    depth++;
  }

  const probed: Record<string, unknown> = {};
  for (const name of ["props", "exports", "tracing", "cache", "waitUntil", "passThroughOnException"]) {
    try {
      const v = (ctx as unknown as Record<string, unknown>)[name];
      probed[name] = {
        type: typeof v,
        constructor: v && typeof v === "object" ? (v as object).constructor?.name : null,
        preview:
          typeof v === "function"
            ? `function ${(v as Function).name}`
            : v && typeof v === "object"
              ? Object.getOwnPropertyNames(v as object)
              : v,
      };
    } catch (err) {
      probed[name] = {
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  return base({
    test_id: "W-CTX-01",
    track: "worker",
    description: "Inspect ExecutionContext shape — props, exports, tracing surfaces",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      own_keys,
      own_symbols,
      proto_chain,
      probed,
    },
  });
};
