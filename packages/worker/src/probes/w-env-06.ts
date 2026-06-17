import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

interface PropInfo {
  name: string;
  kind: "data" | "accessor";
  enumerable: boolean;
  configurable: boolean;
  writable?: boolean;
  type: string;
  constructor: string | null;
}

function inspectObject(obj: object): {
  own_keys: PropInfo[];
  own_symbols: string[];
  proto_chain: Array<{ constructor: string | null; keys: string[] }>;
} {
  const own_keys: PropInfo[] = [];
  for (const key of Object.getOwnPropertyNames(obj)) {
    const desc = Object.getOwnPropertyDescriptor(obj, key);
    if (!desc) continue;
    const isAccessor = "get" in desc || "set" in desc;
    let v: unknown;
    try {
      v = (obj as Record<string, unknown>)[key];
    } catch {
      v = "<threw on access>";
    }
    own_keys.push({
      name: key,
      kind: isAccessor ? "accessor" : "data",
      enumerable: !!desc.enumerable,
      configurable: !!desc.configurable,
      writable: isAccessor ? undefined : !!desc.writable,
      type: typeof v,
      constructor:
        v && typeof v === "object"
          ? (v as object).constructor?.name ?? null
          : null,
    });
  }

  const own_symbols = Object.getOwnPropertySymbols(obj).map((s) => s.toString());

  const proto_chain: Array<{ constructor: string | null; keys: string[] }> = [];
  let p: object | null = Object.getPrototypeOf(obj);
  let depth = 0;
  while (p && p !== Object.prototype && depth < 8) {
    proto_chain.push({
      constructor: p.constructor?.name ?? null,
      keys: Object.getOwnPropertyNames(p),
    });
    p = Object.getPrototypeOf(p);
    depth++;
  }

  return { own_keys, own_symbols, proto_chain };
}

export const wEnv06: Probe = async ({ env, runId }) => {
  const enumerable_keys = Object.keys(env);
  const inspection = inspectObject(env);

  // Compare against what naive Object.keys() would have seen.
  const hidden_from_enumerable = inspection.own_keys
    .filter((k) => !k.enumerable)
    .map((k) => k.name);

  return base({
    test_id: "W-ENV-06",
    track: "worker",
    description: "Deep env walk — accessors, symbols, prototype chain, non-enumerables",
    result: hidden_from_enumerable.length > 0 || inspection.own_symbols.length > 0
      ? "informational"
      : "informational",
    severity: "informational",
    run_id: runId,
    details: {
      enumerable_count: enumerable_keys.length,
      enumerable_keys,
      own_property_count: inspection.own_keys.length,
      own_properties: inspection.own_keys,
      own_symbols: inspection.own_symbols,
      proto_chain: inspection.proto_chain,
      hidden_from_enumerable,
    },
  });
};
