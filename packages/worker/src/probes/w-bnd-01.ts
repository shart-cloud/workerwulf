import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const KNOWN_BINDING_CTORS = new Set([
  "KvNamespace",
  "KVNamespace",
  "R2Bucket",
  "D1Database",
  "DurableObjectNamespace",
  "Queue",
  "Fetcher",
  "AnalyticsEngineDataset",
  "Hyperdrive",
  "VectorizeIndex",
  "RateLimit",
]);

export const wBnd01: Probe = async ({ env, runId }) => {
  const bindings: Array<{
    name: string;
    kind: string;
    methods: string[];
  }> = [];

  for (const k of Object.keys(env)) {
    const v = (env as Record<string, unknown>)[k];
    if (!v || typeof v !== "object") continue;
    const ctor = v.constructor?.name ?? "Object";
    const methods: string[] = [];
    let proto: object | null = Object.getPrototypeOf(v);
    while (proto && proto !== Object.prototype) {
      for (const m of Object.getOwnPropertyNames(proto)) {
        if (m === "constructor") continue;
        const desc = Object.getOwnPropertyDescriptor(proto, m);
        if (desc && typeof desc.value === "function" && !methods.includes(m)) {
          methods.push(m);
        }
      }
      proto = Object.getPrototypeOf(proto);
    }
    bindings.push({
      name: k,
      kind: KNOWN_BINDING_CTORS.has(ctor) ? ctor : `unknown:${ctor}`,
      methods: methods.sort(),
    });
  }

  return base({
    test_id: "W-BND-01",
    track: "worker",
    description: "Enumerate declared bindings on env via prototype-chain walk",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      count: bindings.length,
      bindings,
    },
  });
};
