import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wEnv02: Probe = async ({ env, runId }) => {
  const entries: Array<{
    name: string;
    type: string;
    constructor: string | null;
    preview: string | null;
  }> = [];

  for (const k of Object.keys(env)) {
    const v = (env as Record<string, unknown>)[k];
    const t = typeof v;
    let preview: string | null = null;
    if (t === "string") preview = (v as string).slice(0, 64);
    else if (t === "number" || t === "boolean") preview = String(v);
    entries.push({
      name: k,
      type: t,
      constructor:
        v && typeof v === "object" ? v.constructor?.name ?? null : null,
      preview,
    });
  }

  return base({
    test_id: "W-ENV-02",
    track: "worker",
    description: "Enumerate env bindings: vars, secrets, and resource handles",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      count: entries.length,
      entries,
    },
  });
};
