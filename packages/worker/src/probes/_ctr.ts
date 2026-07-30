// Shared helpers for the Wave 6 Cloudflare Containers exec() probes (W-CTR-*).
// Every probe drives the deliberately-vulnerable CtrTarget container DO over the
// SVC_CTR service binding (packages/container), which wraps `ctx.container.exec()`.
// See docs/wave6-containers-exec.md.

import type { ProbeResult } from "@wulf/shared";
import { base } from "./_helpers.js";

const CTR_ORIGIN = "https://wulf-ctr";

/**
 * The novelty thesis, recorded on every W-CTR probe. On the container-FaaS platforms
 * the function *is* the container, so there is no isolate->container process API to
 * attack; Cloudflare is the only one of the four where sandboxed function code can
 * reach across into a second, far more permissive Linux sandbox it also controls the
 * lifecycle of.
 */
export const CTR_COMPARISON = {
  aws_lambda:
    "N/A — Lambda code runs inside the container; there is no host-side API for function code to spawn processes in a separate container. Spawning is in-process (child_process), inside the same sandbox and the same limits.",
  azure_functions:
    "N/A — custom-container Functions run the function itself; no per-request process-exec API across a runtime/container boundary.",
  gcp_functions:
    "N/A — Cloud Run functions run in the container; no equivalent of a function-owned second sandbox reachable via an exec RPC.",
} as const;

export interface CtrCall {
  ok: boolean;
  status: number;
  body: Record<string, unknown> | string | null;
  error?: string;
}

/**
 * The target Worker gates its whole RPC surface on a shared secret (it exposes
 * arbitrary `sh -c`, so routing config alone is not an acceptable control). A probe
 * therefore needs both the binding and the token; missing either is the same
 * pre-deploy `blocked` condition.
 */
export interface CtrClient {
  svc: Fetcher;
  auth: string;
}

export function ctrClient(env: { SVC_CTR?: Fetcher; WULF_CTR_AUTH?: string }): CtrClient | null {
  if (!env.SVC_CTR || !env.WULF_CTR_AUTH) return null;
  return { svc: env.SVC_CTR, auth: env.WULF_CTR_AUTH };
}

/** One JSON-RPC op against the container DO. `instance` selects a distinct DO. */
export async function ctrCall(
  ctr: CtrClient,
  op: string,
  payload: Record<string, unknown> = {},
  instance?: string,
): Promise<CtrCall> {
  const qs = instance ? `?instance=${encodeURIComponent(instance)}` : "";
  try {
    const res = await ctr.svc.fetch(
      new Request(`${CTR_ORIGIN}/ctr/${op}${qs}`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-wulf-ctr-auth": ctr.auth },
        body: JSON.stringify(payload),
      }),
    );
    const text = await res.text();
    let body: Record<string, unknown> | string;
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      body = text;
    }
    return { ok: res.ok, status: res.status, body };
  } catch (err) {
    return { ok: false, status: 0, body: null, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * W-CTR-03 — stream a body straight into a process's stdin. The body is passed to the
 * container Worker as the request body and handed to `exec(..., { stdin })` without
 * ever being buffered in an isolate.
 */
export async function ctrStdin(
  ctr: CtrClient,
  cmd: string[],
  body: BodyInit,
  extraHeaders: Record<string, string> = {},
): Promise<CtrCall> {
  const url = `${CTR_ORIGIN}/ctr/stdin?cmd=${encodeURIComponent(JSON.stringify(cmd))}`;
  try {
    const res = await ctr.svc.fetch(
      new Request(url, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          "x-wulf-ctr-auth": ctr.auth,
          ...extraHeaders,
        },
        body,
      }),
    );
    const text = await res.text();
    let parsed: Record<string, unknown> | string;
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      parsed = text;
    }
    return { ok: res.ok, status: res.status, body: parsed };
  } catch (err) {
    return { ok: false, status: 0, body: null, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Read a field off a call result without spraying casts through every probe. */
export function field(call: CtrCall, key: string): unknown {
  if (!call.body || typeof call.body !== "object") return undefined;
  return (call.body as Record<string, unknown>)[key];
}

/** An exec record as returned by the container DO's `runExec`. */
export interface ExecRecord {
  ok: boolean;
  cmd: string[];
  pid: number | null;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  stdout_bytes: number;
  stderr_bytes: number;
  truncated: boolean;
  timed_out: boolean;
  duration_ms: number;
  error?: string;
}

export function execOf(call: CtrCall, key: string): ExecRecord | null {
  const raw = field(call, key);
  return raw && typeof raw === "object" ? (raw as ExecRecord) : null;
}

/** The exec ops (`exec_argv`, `exec_shell`, …) return the ExecRecord as the whole body. */
export function recOf(call: CtrCall): ExecRecord | null {
  return call.body && typeof call.body === "object" ? (call.body as unknown as ExecRecord) : null;
}

export function stdoutOf(rec: ExecRecord | null): string {
  return rec?.stdout ?? "";
}

/** Keep probe `details` readable — full output stays in the container DO's response. */
export function clip(text: string, max = 600): string {
  return text.length > max ? `${text.slice(0, max)}…[${text.length} chars]` : text;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Deterministic pseudo-random payload — same run_id gives the same bytes. */
export function payloadBytes(len: number, seed: number): Uint8Array {
  const out = new Uint8Array(len);
  let x = seed >>> 0 || 0x9e3779b9;
  for (let i = 0; i < len; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out[i] = x & 0xff;
  }
  return out;
}

export function seedFrom(runId: string): number {
  let h = 2166136261;
  for (let i = 0; i < runId.length; i++) {
    h ^= runId.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/**
 * Every W-CTR probe is deploy-only: `wrangler dev` has no container runtime and the
 * SVC_CTR binding is optional until wulf-container is deployed. This is the shared
 * pre-deploy verdict, matching the convention used by the W-WC and W-CAP families.
 */
export function ctrBlocked(args: {
  testId: string;
  description: string;
  target: string;
  runId: string;
  tags: string[];
  severity?: ProbeResult["severity"];
}): ProbeResult {
  return base({
    test_id: args.testId,
    track: "worker",
    description: args.description,
    target: args.target,
    result: "blocked",
    severity: args.severity ?? "informational",
    run_id: args.runId,
    tags: args.tags,
    details: {
      error: "SVC_CTR binding not present (expected locally / pre-deploy — Wave 6 is deploy-only)",
    },
    comparison: CTR_COMPARISON,
  });
}

/** Delay used only to let a container-side state change settle. Never a measurement. */
export function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
