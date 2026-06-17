import type { ProbeResult } from "@wulf/shared";
import { CHILD_SOURCE } from "../child-source.js";
import type { WorkerCode, WorkerStub } from "../loader.js";
import type { Env } from "../index.js";

export function now(): string {
  return new Date().toISOString();
}

export function base(p: Omit<ProbeResult, "timestamp">): ProbeResult {
  return { timestamp: now(), ...p };
}

const CHILD_COMPAT_DATE = "2026-05-01";

export interface LoadOpts {
  env?: Record<string, unknown>;
  globalOutbound?: Fetcher | null;
}

export function loadChild(env: Env, opts: LoadOpts = {}): WorkerStub {
  const code: WorkerCode = {
    compatibilityDate: CHILD_COMPAT_DATE,
    mainModule: "index.js",
    modules: { "index.js": CHILD_SOURCE },
    env: opts.env ?? {},
    ...(opts.globalOutbound !== undefined
      ? { globalOutbound: opts.globalOutbound }
      : {}),
  };
  return env.LOADER.load(code);
}

export async function invokeChild(
  stub: WorkerStub,
  cmd: string,
  params: Record<string, string> = {},
): Promise<{ ok: boolean; status: number; body: unknown }> {
  const qs = new URLSearchParams({ cmd, ...params }).toString();
  const url = `https://wulf-child.invalid/?${qs}`;
  const res = await stub.getEntrypoint().fetch(new Request(url));
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = await res.text();
  }
  return { ok: res.ok, status: res.status, body };
}

export function childData<T>(body: unknown): T {
  const envelope = body as { ok?: boolean; data?: T; error?: string };
  if (!envelope || envelope.ok === false) {
    throw new Error(envelope?.error ?? "Dynamic Worker child returned an error");
  }
  return envelope.data as T;
}

export function getChildDoRpc(ctx: ExecutionContext): unknown {
  const exports = (ctx as unknown as {
    exports?: { ChildDoApi?: (opts?: unknown) => unknown };
  }).exports;
  const factory = exports?.ChildDoApi;
  if (!factory) throw new Error("ctx.exports.ChildDoApi is not available");
  return factory();
}
