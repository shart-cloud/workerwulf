import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const KNOWN_CF_GLOBALS = [
  "caches",
  "crypto",
  "navigator",
  "performance",
  "fetch",
  "Request",
  "Response",
  "Headers",
  "URL",
  "URLPattern",
  "WebSocket",
  "WebSocketPair",
  "HTMLRewriter",
  "TransformStream",
  "ReadableStream",
  "WritableStream",
  "CompressionStream",
  "DecompressionStream",
  "TextEncoder",
  "TextDecoder",
  "structuredClone",
  "EventTarget",
  "AbortController",
  "AbortSignal",
  "FormData",
  "Blob",
  "File",
  "atob",
  "btoa",
  "queueMicrotask",
  "setTimeout",
  "setInterval",
  "WebAssembly",
  "SubtleCrypto",
  "CryptoKey",
  "Atomics",
  "SharedArrayBuffer",
  "Worker",
];

export const wEnv03: Probe = async ({ runId }) => {
  const g = globalThis as unknown as Record<string, unknown>;
  const inspected = KNOWN_CF_GLOBALS.map((name) => {
    const v = g[name];
    return {
      name,
      present: name in g,
      type: typeof v,
      constructor:
        v && typeof v === "object" ? v.constructor?.name ?? null : null,
    };
  });

  const cfHeader = (g["navigator"] as { userAgent?: string } | undefined)
    ?.userAgent;

  return base({
    test_id: "W-ENV-03",
    track: "worker",
    description: "Probe known and Cloudflare-injected globals",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      navigator_user_agent: cfHeader ?? null,
      globals: inspected,
      missing: inspected.filter((g) => !g.present).map((g) => g.name),
    },
  });
};
