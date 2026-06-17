import { Container, getContainer } from "@cloudflare/containers";

export interface Env {
  CODESHIELD: DurableObjectNamespace<CodeshieldContainer>;
}

type Severity = "info" | "warning" | "error";
const SEVERITY_RANK: Record<Severity, number> = { info: 1, warning: 2, error: 3 };

interface ContainerIssue {
  rule_id: string;
  severity: Severity;
  line?: number;
  message: string;
  cwe?: string;
  source: "codeshield" | "wulf-semgrep";
}

interface ContainerScanResponse {
  issues: ContainerIssue[];
  severity_max: Severity | null;
  count_by_severity: Record<Severity, number>;
  latency_ms: number;
}

export class CodeshieldContainer extends Container {
  defaultPort = 8000;
  sleepAfter = "15m";

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL DEFAULT (datetime('now')),
        probe_id TEXT,
        code_hash TEXT,
        code_preview TEXT,
        severity_max TEXT,
        issue_count INTEGER,
        issue_summary_json TEXT,
        min_severity TEXT,
        policy TEXT,
        blocked INTEGER DEFAULT 0,
        latency_ms INTEGER
      )
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return this.containerFetch(request);
    }

    if (url.pathname === "/scan" && request.method === "POST") {
      return this.handleScan(request);
    }

    if (url.pathname === "/report") {
      return this.handleReport(url);
    }

    if (url.pathname === "/reset" && request.method === "POST") {
      this.ensureSchema();
      this.ctx.storage.sql.exec("DELETE FROM scans");
      return json({ ok: true, message: "stats reset" });
    }

    return json({ error: "not_found", path: url.pathname }, 404);
  }

  private async handleScan(request: Request): Promise<Response> {
    this.ensureSchema();

    const body = (await request.json()) as {
      code: string;
      language?: string;
      probe_id?: string;
      min_severity?: Severity;
      policy?: "block" | "log" | "pass";
    };

    const minSeverity = body.min_severity ?? "warning";
    const policy = body.policy ?? "log";

    const containerRes = await this.containerFetch(
      new Request("http://container/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: body.code, language: body.language ?? "javascript" }),
      }),
    );

    if (!containerRes.ok) {
      const errText = await containerRes.text();
      return json({ error: "container_error", detail: errText }, 502);
    }

    const result = (await containerRes.json()) as ContainerScanResponse;

    const meetsThreshold =
      result.severity_max != null &&
      SEVERITY_RANK[result.severity_max] >= SEVERITY_RANK[minSeverity];
    const blocked = policy === "block" && meetsThreshold ? 1 : 0;

    const codeHash = await sha256(body.code);
    const issueSummary = result.issues.slice(0, 20).map((i) => ({
      rule_id: i.rule_id,
      severity: i.severity,
      cwe: i.cwe,
      source: i.source,
    }));

    this.ctx.storage.sql.exec(
      `INSERT INTO scans
        (probe_id, code_hash, code_preview, severity_max, issue_count, issue_summary_json, min_severity, policy, blocked, latency_ms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      body.probe_id ?? null,
      codeHash,
      body.code.slice(0, 200),
      result.severity_max,
      result.issues.length,
      JSON.stringify(issueSummary),
      minSeverity,
      policy,
      blocked,
      result.latency_ms,
    );

    return json({
      severity_max: result.severity_max,
      issue_count: result.issues.length,
      issues: result.issues,
      count_by_severity: result.count_by_severity,
      latency_ms: result.latency_ms,
      blocked,
      meets_threshold: meetsThreshold,
      min_severity: minSeverity,
      policy,
    });
  }

  private handleReport(url: URL): Response {
    this.ensureSchema();

    const probeId = url.searchParams.get("probe_id");
    const whereClause = probeId ? "WHERE probe_id = ?" : "";
    const args: string[] = probeId ? [probeId] : [];

    const total = this.ctx.storage.sql
      .exec(`SELECT COUNT(*) as n FROM scans ${whereClause}`, ...args)
      .one() as { n: number };

    const bySeverity = this.ctx.storage.sql
      .exec(
        `SELECT severity_max, COUNT(*) as n FROM scans ${whereClause} GROUP BY severity_max`,
        ...args,
      )
      .toArray() as { severity_max: string | null; n: number }[];

    const blocked = this.ctx.storage.sql
      .exec(
        `SELECT COUNT(*) as n FROM scans WHERE blocked = 1 ${probeId ? "AND probe_id = ?" : ""}`,
        ...args,
      )
      .one() as { n: number };

    const avgLatency = this.ctx.storage.sql
      .exec(
        `SELECT AVG(latency_ms) as avg_ms, MIN(latency_ms) as min_ms, MAX(latency_ms) as max_ms FROM scans ${whereClause}`,
        ...args,
      )
      .one() as { avg_ms: number; min_ms: number; max_ms: number };

    const recent = this.ctx.storage.sql
      .exec(
        `SELECT probe_id, severity_max, issue_count, blocked, ts, code_preview, issue_summary_json
         FROM scans ${whereClause}
         ORDER BY id DESC LIMIT 50`,
        ...args,
      )
      .toArray();

    return json({
      total: total.n,
      by_severity: Object.fromEntries(bySeverity.map((r) => [r.severity_max ?? "none", r.n])),
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
    const container = getContainer(env.CODESHIELD, guardId);

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
