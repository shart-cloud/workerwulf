import { decodeBatch, type Batch } from "./batch.js";
import { hubFor, type Env } from "./env.js";
import type { FindingState } from "./store.js";

export { ScanHub } from "./hub.js";
export { ScanWorkflow } from "./workflow.js";
export type { Env } from "./env.js";

/** `wulf scan --push`: a scan collected and summarized by the CLI. */
interface PushRequest {
  accountId: string;
  startedAt: string;
  batches: unknown[];
}

const STATES = new Set<FindingState>(["open", "resolved", "suppressed"]);

/** Every request needs `Authorization: Bearer <WULF_TOKEN>`. With no token configured, nothing is served. */
function authorized(request: Request, env: Env): boolean {
  if (!env.WULF_TOKEN) return false;
  const enc = new TextEncoder();
  const got = enc.encode(request.headers.get("authorization") ?? "");
  const want = enc.encode(`Bearer ${env.WULF_TOKEN}`);
  return got.byteLength === want.byteLength && crypto.subtle.timingSafeEqual(got, want);
}

const bad = (message: string, status = 400) => Response.json({ error: message }, { status });

/** Workflow instance ids allow `[A-Za-z0-9_-]`, up to 100 characters. */
const instanceId = (prefix: string, at: Date) => `${prefix}-${at.toISOString().replace(/[:.]/g, "-")}`;

export default {
  async fetch(request, env): Promise<Response> {
    if (!authorized(request, env)) return new Response("unauthorized", { status: 401 });
    const url = new URL(request.url);
    const path = url.pathname;
    const hub = hubFor(env, env.CLOUDFLARE_ACCOUNT_ID);

    if (request.method === "GET") {
      if (path === "/health") return new Response("ok");
      if (path === "/findings") {
        const state = url.searchParams.get("state");
        if (state !== null && !STATES.has(state as FindingState)) return bad(`unknown state ${state}`);
        return Response.json(await hub.findings((state ?? undefined) as FindingState | undefined));
      }
      if (path === "/scans") return Response.json(await hub.scans());
      const scan = path.match(/^\/scans\/([A-Za-z0-9_-]+)(\/occurrences)?$/);
      if (scan) {
        const id = scan[1]!;
        if (scan[2]) return Response.json(await hub.occurrences(id));
        const record = await hub.scan(id);
        return record ? Response.json(record) : bad(`unknown scan ${id}`, 404);
      }
      return bad("not found", 404);
    }

    if (request.method !== "POST") return bad("not found", 404);

    if (path === "/scans") {
      const id = `manual-${crypto.randomUUID()}`;
      await env.SCAN_WORKFLOW.create({ id, params: {} });
      return Response.json({ scan_id: id }, { status: 202 });
    }

    if (path === "/findings/suppress" || path === "/findings/unsuppress") {
      const body = (await request.json()) as { key?: unknown; reason?: unknown };
      if (typeof body.key !== "string") return bad("key is required");
      if (path === "/findings/suppress") {
        if (typeof body.reason !== "string" || body.reason.trim() === "") return bad("reason is required");
        const f = await hub.suppress(body.key, body.reason);
        return f ? Response.json(f) : bad(`unknown finding ${body.key}`, 404);
      }
      const f = await hub.unsuppress(body.key);
      return f ? Response.json(f) : bad(`unknown finding ${body.key}`, 404);
    }

    if (path === "/ingest/scan") {
      const body = (await request.json()) as PushRequest;
      if (body.accountId !== env.CLOUDFLARE_ACCOUNT_ID) {
        return bad(`this hub scans account ${env.CLOUDFLARE_ACCOUNT_ID}, not ${String(body.accountId)}`, 403);
      }
      if (typeof body.startedAt !== "string" || !Array.isArray(body.batches)) {
        return bad("startedAt and batches are required");
      }
      let batches: Batch[];
      try {
        batches = body.batches.map(decodeBatch);
      } catch (err) {
        return bad(`invalid batch: ${(err as Error).message}`);
      }
      const scanId = instanceId("push", new Date()) + `-${crypto.randomUUID().slice(0, 8)}`;
      await hub.begin(scanId, body.accountId, body.startedAt, "push");
      for (const [i, batch] of batches.entries()) await hub.append(scanId, i, batch);
      const result = await hub.complete(scanId, new Date().toISOString());
      return Response.json(result);
    }

    return bad("not found", 404);
  },

  async scheduled(controller, env): Promise<void> {
    const id = instanceId("cron", new Date(controller.scheduledTime));
    try {
      await env.SCAN_WORKFLOW.create({ id, params: {} });
    } catch (err) {
      // A cron retry for the same tick finds its instance already created.
      if (!String(err).includes("already exists")) throw err;
    }
  },
} satisfies ExportedHandler<Env>;
