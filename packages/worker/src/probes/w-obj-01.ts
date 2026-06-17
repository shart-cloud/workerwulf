import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

function deepWalk(obj: unknown, maxDepth = 3): unknown {
  if (obj === null || obj === undefined) return String(obj);
  if (maxDepth <= 0) return "[max depth]";

  if (typeof obj === "function") {
    return {
      type: "function",
      name: obj.name || "(anonymous)",
      length: obj.length,
    };
  }

  if (typeof obj !== "object") {
    return { type: typeof obj, value: String(obj) };
  }

  const out: Record<string, unknown> = {};
  const names = Object.getOwnPropertyNames(obj).sort();
  for (const n of names) {
    try {
      const v = (obj as Record<string, unknown>)[n];
      if (typeof v === "function") {
        out[n] = {
          type: "function",
          name: (v as Function).name || "(anonymous)",
          length: (v as Function).length,
        };
      } else if (typeof v === "object" && v !== null) {
        out[n] = deepWalk(v, maxDepth - 1);
      } else {
        out[n] = { type: typeof v, value: v };
      }
    } catch (err) {
      out[n] = {
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  const symbols = Object.getOwnPropertySymbols(obj);
  if (symbols.length > 0) {
    out["__symbols__"] = symbols.map((s) => s.toString());
  }

  const proto = Object.getPrototypeOf(obj);
  if (proto && proto !== Object.prototype) {
    out["__proto__"] = deepWalk(proto, maxDepth - 2);
  }

  if (obj.constructor && obj.constructor !== Object) {
    out["__constructor__"] =
      typeof obj.constructor === "function"
        ? obj.constructor.name
        : String(obj.constructor);
  }

  return out;
}

export const wObj01: Probe = async ({ runId }) => {
  const g = globalThis as unknown as Record<string, unknown>;
  const cf = typeof g.Cloudflare === "object" && g.Cloudflare !== null
    ? g.Cloudflare
    : null;

  if (!cf) {
    return base({
      test_id: "W-OBJ-01",
      track: "worker",
      description: "Deep walk of the Cloudflare global object",
      result: "informational",
      severity: "informational",
      run_id: runId,
      details: {
        present: false,
        note: "Cloudflare global not found on globalThis",
      },
    });
  }

  const ownProps = Object.getOwnPropertyNames(cf).sort();
  const syms = Object.getOwnPropertySymbols(cf).map((s) => s.toString());

  const typed: Record<string, string> = {};
  for (const p of ownProps) {
    const v = (cf as Record<string, unknown>)[p];
    if (typeof v === "function") typed[p] = "function";
    else if (typeof v === "object" && v !== null) typed[p] = (v as object).constructor?.name ?? "object";
    else typed[p] = typeof v;
  }

  const walk = deepWalk(cf, 3);

  return base({
    test_id: "W-OBJ-01",
    track: "worker",
    description: "Deep walk of the Cloudflare global object",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      present: true,
      own_properties: ownProps,
      own_symbols: syms,
      property_types: typed,
      total_properties: ownProps.length,
      deep_walk: walk,
    },
  });
};
