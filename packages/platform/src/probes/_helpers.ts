import { buildCallbackHttpTarget } from "@wulf/shared";
import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../dispatch.js";
import type { ProbeCtx } from "./index.js";

export type NamespaceMode = "untrusted" | "trusted";

export function base(p: Omit<ProbeResult, "timestamp">): ProbeResult {
  return { timestamp: new Date().toISOString(), ...p };
}

export function namespaceMode(req: Request): NamespaceMode {
  const raw = new URL(req.url).searchParams.get("namespace");
  return raw === "trusted" ? "trusted" : "untrusted";
}

export function dispatcher(env: Env, mode: NamespaceMode): DispatchNamespace {
  if (mode === "trusted") {
    if (!env.DISPATCHER_TRUSTED) throw new Error("DISPATCHER_TRUSTED binding is not configured");
    return env.DISPATCHER_TRUSTED;
  }
  return env.DISPATCHER;
}

export async function invokeTenant<T = unknown>(
  c: ProbeCtx,
  tenant: "tenant-prey" | "tenant-victim",
  cmd: string,
  params: Record<string, string> = {},
  opts: { mode?: NamespaceMode; limits?: DynamicDispatchLimits } = {},
): Promise<{ ok: boolean; status: number; body: T }> {
  const mode = opts.mode ?? namespaceMode(c.req);
  const ns = dispatcher(c.env, mode);
  const fetcher = ns.get(
    tenant,
    {},
    {
      outbound: {
        customer_name: tenant,
        url: c.req.url,
        run_id: c.runId,
        test_id: new URL(c.req.url).pathname.split("/").pop() ?? "unknown",
      },
      ...(opts.limits ? { limits: opts.limits } : {}),
    },
  );
  const qs = new URLSearchParams(params).toString();
  const url = `https://${tenant}.wulf.invalid/cmd/${cmd}${qs ? `?${qs}` : ""}`;
  const res = await fetcher.fetch(new Request(url));
  const body = (await readBody(res)) as T;
  return { ok: res.ok, status: res.status, body };
}

export function callbackTarget(c: ProbeCtx, testId: string, path = "/platform-callback"): string {
  return c.env.WULF_CALLBACK_HTTP_BASE
    ? buildCallbackHttpTarget({ base: c.env.WULF_CALLBACK_HTTP_BASE, testId, runId: c.runId, track: "platform", extra: { path } })
    : `http://callback.wulf.shart.cloud${path}`;
}

export async function checkCallback(c: ProbeCtx, testId: string, since: string): Promise<Record<string, unknown>> {
  if (!c.env.WULF_CALLBACK_HTTP_BASE) return { checked: false, reason: "WULF_CALLBACK_HTTP_BASE unset" };
  try {
    const url = new URL("/check", c.env.WULF_CALLBACK_HTTP_BASE);
    url.searchParams.set("test_id", testId);
    url.searchParams.set("run_id", c.runId);
    url.searchParams.set("since", since);
    const res = await fetch(url.toString());
    return { checked: true, status: res.status, ...((await res.json()) as Record<string, unknown>) };
  } catch (err) {
    return { checked: true, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function outboundLogKeys(env: Env, testId: string, runId: string): Promise<string[]> {
  if (!env.OUTBOUND_LOG) return [];
  const prefix = `outbound/${testId}/${runId}/`;
  const listed = await env.OUTBOUND_LOG.list({ prefix, limit: 100 });
  return listed.objects.map((obj) => obj.key);
}

export async function outboundLogEvents(env: Env, testId: string, runId: string): Promise<Record<string, unknown>[]> {
  if (!env.OUTBOUND_LOG) return [];
  const keys = await outboundLogKeys(env, testId, runId);
  const events: Record<string, unknown>[] = [];
  for (const key of keys) {
    const obj = await env.OUTBOUND_LOG.get(key);
    const text = await obj?.text();
    if (!text) continue;
    try {
      events.push({ key, ...(JSON.parse(text) as Record<string, unknown>) });
    } catch {
      events.push({ key, parse_error: true, body_preview: text.slice(0, 500) });
    }
  }
  return events;
}

async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
