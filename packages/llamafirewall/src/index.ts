import { Container, getContainer } from "@cloudflare/containers";

export interface Env {
  LLAMAFIREWALL: DurableObjectNamespace<LlamaFirewallContainer>;
  // Per-Worker secret set via `wrangler secret put CF_API_TOKEN`.
  // Scope: Workers AI:Read. Used by AlignmentCheck to call the OpenAI-compatible
  // Workers AI endpoint at https://api.cloudflare.com/client/v4/accounts/<acct>/ai/v1.
  CF_API_TOKEN: string;
}

const CLOUDFLARE_ACCOUNT_ID = "11caecd272df7dbdcc636034c25b1f1c";

type Decision = "allow" | "block" | "human_in_the_loop";

interface ScanResult {
  decision: Decision;
  reason: string;
  score: number;
  scanner_breakdown?: Record<string, { decision: Decision; reason: string; score: number }>;
  latency_ms: number;
  error?: string;
}

interface ScanTraceResult extends ScanResult {}

export class LlamaFirewallContainer extends Container<Env> {
  defaultPort = 8000;
  sleepAfter = "15m";

  // Set envVars in the constructor so the runtime's auto-start path picks them
  // up on every cold-start (container sleeps after `sleepAfter` and is restarted
  // on the next request). A boolean flag like `envSeeded` won't work because
  // the flag persists across hibernation but the container process does not.
  constructor(ctx: DurableObjectState<Env>, env: Env) {
    super(ctx, env);
    this.envVars = {
      CF_API_TOKEN: env.CF_API_TOKEN,
      CLOUDFLARE_ACCOUNT_ID,
    };
  }

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL DEFAULT (datetime('now')),
        probe_id TEXT,
        endpoint TEXT,
        content_hash TEXT,
        content_preview TEXT,
        decision TEXT,
        reason TEXT,
        score REAL,
        scanner_breakdown_json TEXT,
        latency_ms INTEGER,
        policy TEXT,
        blocked INTEGER DEFAULT 0
      )
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/report") {
      // SQLite-only — no container needed.
      return this.handleReport(url);
    }
    if (url.pathname === "/reset" && request.method === "POST") {
      this.ensureSchema();
      this.ctx.storage.sql.exec("DELETE FROM scans");
      return json({ ok: true, message: "stats reset" });
    }

    // Every other path hits the container. PG2 + transformers + uvicorn boot
    // takes 30-60s; the default auto-start window inside containerFetch can be
    // too tight. Call startAndWaitForPorts explicitly (idempotent — no-op when
    // the container is already up) before each container-bound request.
    await this.startAndWaitForPorts();

    if (url.pathname === "/health" || url.pathname.startsWith("/debug/")) {
      return this.containerFetch(request);
    }

    if (url.pathname === "/scan-input" && request.method === "POST") {
      return this.handleScan(request, "scan-input");
    }
    if (url.pathname === "/scan-output" && request.method === "POST") {
      return this.handleScan(request, "scan-output");
    }
    if (url.pathname === "/scan-trace" && request.method === "POST") {
      return this.handleScanTrace(request);
    }

    return json({ error: "not_found", path: url.pathname }, 404);
  }

  private async handleScan(
    request: Request,
    endpoint: "scan-input" | "scan-output",
  ): Promise<Response> {
    this.ensureSchema();

    const body = (await request.json()) as {
      text: string;
      probe_id?: string;
      policy?: "block" | "log" | "pass";
    };
    const policy = body.policy ?? "log";

    const containerRes = await this.containerFetch(
      new Request(`http://container/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: body.text }),
      }),
    );

    if (!containerRes.ok) {
      const errText = await containerRes.text();
      return json({ error: "container_error", detail: errText }, 502);
    }

    const result = (await containerRes.json()) as ScanResult;
    const blocked = policy === "block" && result.decision === "block" ? 1 : 0;

    await this.logScan(endpoint, body.text, body.probe_id, result, policy, blocked);

    return json({ ...result, blocked, policy });
  }

  private async handleScanTrace(request: Request): Promise<Response> {
    this.ensureSchema();

    const body = (await request.json()) as {
      messages: { role: "user" | "assistant"; content: string }[];
      probe_id?: string;
      policy?: "block" | "log" | "pass";
    };
    const policy = body.policy ?? "log";

    const containerRes = await this.containerFetch(
      new Request("http://container/scan-trace", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: body.messages }),
      }),
    );

    if (!containerRes.ok) {
      const errText = await containerRes.text();
      return json({ error: "container_error", detail: errText }, 502);
    }

    const result = (await containerRes.json()) as ScanTraceResult;
    const blocked = policy === "block" && result.decision === "block" ? 1 : 0;

    const traceSummary = body.messages
      .map((m) => `${m.role}:${m.content.slice(0, 40)}`)
      .join(" | ");
    await this.logScan("scan-trace", traceSummary, body.probe_id, result, policy, blocked);

    return json({ ...result, blocked, policy });
  }

  private async logScan(
    endpoint: string,
    content: string,
    probeId: string | undefined,
    result: ScanResult,
    policy: string,
    blocked: number,
  ): Promise<void> {
    const contentHash = await sha256(content);
    this.ctx.storage.sql.exec(
      `INSERT INTO scans
        (probe_id, endpoint, content_hash, content_preview, decision, reason, score,
         scanner_breakdown_json, latency_ms, policy, blocked)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      probeId ?? null,
      endpoint,
      contentHash,
      content.slice(0, 200),
      result.decision,
      result.reason,
      result.score,
      result.scanner_breakdown ? JSON.stringify(result.scanner_breakdown) : null,
      result.latency_ms,
      policy,
      blocked,
    );
  }

  private handleReport(url: URL): Response {
    this.ensureSchema();

    const probeId = url.searchParams.get("probe_id");
    const whereClause = probeId ? "WHERE probe_id = ?" : "";
    const args: string[] = probeId ? [probeId] : [];

    const total = this.ctx.storage.sql
      .exec(`SELECT COUNT(*) as n FROM scans ${whereClause}`, ...args)
      .one() as { n: number };

    const byDecision = this.ctx.storage.sql
      .exec(
        `SELECT decision, COUNT(*) as n FROM scans ${whereClause} GROUP BY decision`,
        ...args,
      )
      .toArray() as { decision: string; n: number }[];

    const byEndpoint = this.ctx.storage.sql
      .exec(
        `SELECT endpoint, decision, COUNT(*) as n FROM scans ${whereClause} GROUP BY endpoint, decision`,
        ...args,
      )
      .toArray() as { endpoint: string; decision: string; n: number }[];

    const byReason = this.ctx.storage.sql
      .exec(
        `SELECT reason, COUNT(*) as n FROM scans
         WHERE reason IS NOT NULL ${probeId ? "AND probe_id = ?" : ""}
         GROUP BY reason ORDER BY n DESC`,
        ...args,
      )
      .toArray() as { reason: string; n: number }[];

    const blocked = this.ctx.storage.sql
      .exec(
        `SELECT COUNT(*) as n FROM scans WHERE blocked = 1 ${probeId ? "AND probe_id = ?" : ""}`,
        ...args,
      )
      .one() as { n: number };

    const avgLatency = this.ctx.storage.sql
      .exec(
        `SELECT AVG(latency_ms) as avg_ms, MIN(latency_ms) as min_ms, MAX(latency_ms) as max_ms
         FROM scans ${whereClause}`,
        ...args,
      )
      .one() as { avg_ms: number; min_ms: number; max_ms: number };

    const recent = this.ctx.storage.sql
      .exec(
        `SELECT probe_id, endpoint, decision, reason, score, blocked, latency_ms, content_preview, ts
         FROM scans ${whereClause}
         ORDER BY id DESC LIMIT 50`,
        ...args,
      )
      .toArray();

    return json({
      total: total.n,
      by_decision: Object.fromEntries(byDecision.map((r) => [r.decision, r.n])),
      by_endpoint: byEndpoint,
      by_reason: Object.fromEntries(byReason.map((r) => [r.reason, r.n])),
      blocked: blocked.n,
      latency: avgLatency,
      recent,
    });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const guardId = url.searchParams.get("guard_id") ?? "default";
    const container = getContainer(env.LLAMAFIREWALL, guardId);

    url.searchParams.delete("guard_id");
    const cleanRequest = new Request(url.toString(), request);

    return container.fetch(cleanRequest);
  },
};

async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
