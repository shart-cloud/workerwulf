import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const COMMON_NAMES = [
  "DB",
  "KV",
  "CACHE",
  "BUCKET",
  "STORAGE",
  "QUEUE",
  "ANALYTICS",
  "AI",
  "VECTORIZE",
  "HYPERDRIVE",
  "RATE_LIMITER",
  "SESSION",
  "AUTH",
  "USERS",
  "SECRETS",
  "ADMIN",
  "API_KEY",
  "STRIPE_SECRET",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "JWT_SECRET",
  "DATABASE_URL",
  "REDIS_URL",
];

export const wBnd02: Probe = async ({ env, runId }) => {
  const declared = new Set(Object.keys(env));
  const probes = COMMON_NAMES.map((name) => {
    const present = name in env;
    const v = (env as Record<string, unknown>)[name];
    return {
      name,
      declared: declared.has(name),
      present,
      type: typeof v,
      preview:
        typeof v === "string" ? (v as string).slice(0, 32) : null,
    };
  });

  const hits = probes.filter((p) => p.present);

  return base({
    test_id: "W-BND-02",
    track: "worker",
    description: "Probe env for undeclared bindings using common names",
    result: hits.length > 0 ? "informational" : "blocked",
    severity: hits.length > 0 ? "low" : "informational",
    run_id: runId,
    details: {
      probed: COMMON_NAMES.length,
      hits: hits.length,
      probes,
    },
  });
};
