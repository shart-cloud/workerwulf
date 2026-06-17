import type { ProbeResult } from "@wulf/shared";
import { WorkerEntrypoint } from "cloudflare:workers";
import type { WorkerLoader } from "./loader.js";
import { probes } from "./probes/index.js";

export interface Env {
  LOADER: WorkerLoader;
  CHILD_DO: DurableObjectNamespace;
  CHILD_DO_SECURE: DurableObjectNamespace;
  PARENT_KV: KVNamespace;
  PARENT_R2: R2Bucket;
  LOGPUSH_R2: R2Bucket;
  PARENT_D1: D1Database;
  PARENT_SECRET_DECOY: string;
  WULF_CALLBACK_HTTP_BASE?: string;
  WULF_DNS_EXFIL_ZONE?: string;
  [key: string]: unknown;
}

export class ChildDoApi extends WorkerEntrypoint<Env> {
  async execSql(args: { name?: string; cmd?: string; input?: string }): Promise<unknown> {
    const stub = getNamedStub(this.env.CHILD_DO, args.name ?? "dyn-test");
    const path = `/${args.cmd ?? "classic-sqli"}`;
    const query = args.input ? `?input=${encodeURIComponent(args.input)}` : "";
    return doFetch(stub, `http://do${path}${query}`);
  }

  async stubEnum(): Promise<unknown> {
    const stub = getNamedStub(this.env.CHILD_DO, "enum-test");
    const methods: string[] = [];
    let proto: object | null = Object.getPrototypeOf(stub);
    while (proto && proto !== Object.prototype) {
      for (const method of Object.getOwnPropertyNames(proto)) {
        if (method === "constructor") continue;
        const desc = Object.getOwnPropertyDescriptor(proto, method);
        if (desc && typeof desc.value === "function" && !methods.includes(method)) {
          methods.push(method);
        }
      }
      proto = Object.getPrototypeOf(proto);
    }
    return {
      binding: "CHILD_DO_RPC",
      stub_methods: methods.sort(),
      stub_constructor: stub.constructor && stub.constructor.name,
    };
  }

  async crossObject(args: { targetName?: string }): Promise<unknown> {
    const originalName = "original";
    const targetName = args.targetName ?? "other";
    const markerUser = `marker-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const originalId = this.env.CHILD_DO.idFromName(originalName);
    const guessedId = this.env.CHILD_DO.idFromName(targetName);
    const originalStub = this.env.CHILD_DO.get(originalId);
    const guessedStub = this.env.CHILD_DO.get(guessedId);

    await doFetch(originalStub, "http://do/init-schema");
    await doFetch(guessedStub, "http://do/init-schema");
    const payload = `admin'; INSERT INTO users (username, password, secret) VALUES ('${markerUser}', 'marker', 'd-do-03-marker'); SELECT * FROM users WHERE username = 'admin`;
    await doFetch(originalStub, `http://do/stacked-query?input=${encodeURIComponent(payload)}`);
    const guessed = await doFetch<{ rows?: unknown[] }>(
      guessedStub,
      `http://do/classic-sqli?input=${encodeURIComponent(markerUser)}`,
    );

    return {
      binding: "CHILD_DO_RPC",
      original_name: originalName,
      guessed_name: targetName,
      original_id: originalId.toString(),
      guessed_id: guessedId.toString(),
      ids_equal: originalId.toString() === guessedId.toString(),
      marker_user: markerUser,
      marker_visible_from_guessed_object: (guessed.rows ?? []).length > 0,
      note: "The child only receives this RPC facade. It cannot construct arbitrary DO IDs unless this facade exposes that behavior.",
    };
  }

  async webSocketHibernation(): Promise<unknown> {
    return {
      binding: "CHILD_DO_RPC",
      websocket_upgrade_supported: null,
      hibernation_api_callable: false,
      note: "The child has no DO ctx, so acceptWebSocket()/hibernation APIs are not directly callable through this facade.",
    };
  }

  async alarmSchedule(): Promise<unknown> {
    return {
      binding: "CHILD_DO_RPC",
      alarm_api_callable: false,
      note: "The child has no DO ctx/storage reference, so ctx.storage.setAlarm() is not directly callable through this facade.",
    };
  }
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/" || url.pathname === "/probes") {
      return json({ probes: Object.keys(probes) });
    }

    if (url.pathname === "/relay") {
      const headers: Record<string, string> = {};
      for (const [k, v] of req.headers) {
        headers[k] = v;
      }
      return json({
        relay: "wulf-dynamic-parent",
        method: req.method,
        url: req.url,
        headers,
      });
    }

    const match = url.pathname.match(/^\/probe\/([A-Z0-9-]+)$/);
    if (!match) return json({ error: "not_found" }, 404);

    const testId = match[1]!;
    const probe = probes[testId];
    if (!probe) return json({ error: "unknown_test_id", test_id: testId }, 404);

    const runId = url.searchParams.get("run_id") ?? crypto.randomUUID();

    try {
      const result = await probe({ env, ctx, req, runId });
      return json(result satisfies ProbeResult);
    } catch (err) {
      return json(
        {
          test_id: testId,
          error: "probe_threw",
          message: err instanceof Error ? err.message : String(err),
          stack: err instanceof Error ? err.stack : undefined,
        },
        500,
      );
    }
  },
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function getNamedStub(ns: DurableObjectNamespace, name: string): DurableObjectStub {
  return ns.get(ns.idFromName(name));
}

async function doFetch<T = unknown>(stub: DurableObjectStub, input: RequestInfo | URL): Promise<T> {
  const res = await stub.fetch(input);
  const body = (await res.json()) as { ok?: boolean; data?: T; error?: string };
  if (!res.ok || body.ok === false) {
    throw new Error(body.error ?? `Durable Object request failed with ${res.status}`);
  }
  return body.data as T;
}
