import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wEnv01: Probe = async ({ runId }) => {
  const g = globalThis as unknown as Record<string, unknown>;
  const names = Object.getOwnPropertyNames(g).sort();
  const byKind: Record<string, string[]> = {};
  for (const n of names) {
    const v = g[n];
    const kind = v === null ? "null" : typeof v;
    (byKind[kind] ??= []).push(n);
  }

  return base({
    test_id: "W-ENV-01",
    track: "worker",
    description: "Enumerate global objects and constructors in the V8 isolate",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      total: names.length,
      names,
      by_kind: byKind,
    },
  });
};
