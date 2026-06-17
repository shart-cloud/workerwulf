import { Container, getContainer } from "@cloudflare/containers";

export interface Env {
  PROMPT_GUARD: DurableObjectNamespace<PromptGuardContainer>;
}

export class PromptGuardContainer extends Container {
  defaultPort = 8000;
  sleepAfter = "15m";

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS classifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL DEFAULT (datetime('now')),
        probe_id TEXT,
        phase TEXT,
        text_hash TEXT,
        text_preview TEXT,
        label TEXT,
        score REAL,
        logit_benign REAL,
        logit_malicious REAL,
        threshold REAL,
        latency_ms INTEGER,
        policy TEXT,
        blocked INTEGER DEFAULT 0
      )
    `);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return this.containerFetch(request);
    }

    if (url.pathname === "/classify" && request.method === "POST") {
      return this.handleClassify(request);
    }

    if (url.pathname === "/classify-both" && request.method === "POST") {
      return this.handleClassifyBoth(request);
    }

    if (url.pathname === "/report") {
      return this.handleReport(url);
    }

    if (url.pathname === "/reset" && request.method === "POST") {
      this.ensureSchema();
      this.ctx.storage.sql.exec("DELETE FROM classifications");
      return json({ ok: true, message: "stats reset" });
    }

    return json({ error: "not_found", path: url.pathname }, 404);
  }

  private async handleClassify(request: Request): Promise<Response> {
    this.ensureSchema();

    const body = (await request.json()) as {
      text: string;
      probe_id?: string;
      phase?: string;
      threshold?: number;
      policy?: string;
    };

    const threshold = body.threshold ?? 0.5;
    const policy = body.policy ?? "log";
    const phase = body.phase ?? "input";

    const containerRes = await this.containerFetch(
      new Request("http://container/classify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: body.text }),
      }),
    );

    if (!containerRes.ok) {
      const errText = await containerRes.text();
      return json({ error: "container_error", detail: errText }, 502);
    }

    const result = (await containerRes.json()) as {
      label: string;
      score: number;
      logits: { benign: number; malicious: number };
      latency_ms: number;
    };

    const maliciousProb = softmax(result.logits.malicious, result.logits.benign);
    const effectiveLabel = maliciousProb >= threshold ? "MALICIOUS" : "BENIGN";
    const blocked = policy === "block" && effectiveLabel === "MALICIOUS" ? 1 : 0;

    const textHash = await sha256(body.text);
    this.ctx.storage.sql.exec(
      `INSERT INTO classifications
        (probe_id, phase, text_hash, text_preview, label, score, logit_benign, logit_malicious, threshold, latency_ms, policy, blocked)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      body.probe_id ?? null,
      phase,
      textHash,
      body.text.slice(0, 100),
      effectiveLabel,
      maliciousProb,
      result.logits.benign,
      result.logits.malicious,
      threshold,
      result.latency_ms,
      policy,
      blocked,
    );

    return json({
      label: effectiveLabel,
      score: maliciousProb,
      logits: result.logits,
      latency_ms: result.latency_ms,
      blocked,
      policy,
      threshold,
    });
  }

  private async handleClassifyBoth(request: Request): Promise<Response> {
    this.ensureSchema();

    const body = (await request.json()) as {
      input_text: string;
      output_text: string;
      probe_id?: string;
      threshold?: number;
      policy?: string;
    };

    const threshold = body.threshold ?? 0.5;
    const policy = body.policy ?? "log";

    const [inputRes, outputRes] = await Promise.all([
      this.classifyOne(body.input_text, body.probe_id, "input", threshold, policy),
      this.classifyOne(body.output_text, body.probe_id, "output", threshold, policy),
    ]);

    const wouldBlock =
      policy === "block" &&
      (inputRes.label === "MALICIOUS" || outputRes.label === "MALICIOUS");

    return json({
      input: inputRes,
      output: outputRes,
      would_block: wouldBlock,
    });
  }

  private async classifyOne(
    text: string,
    probeId: string | undefined,
    phase: string,
    threshold: number,
    policy: string,
  ): Promise<{
    label: string;
    score: number;
    logits: { benign: number; malicious: number };
    latency_ms: number;
    blocked: number;
  }> {
    const containerRes = await this.containerFetch(
      new Request("http://container/classify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      }),
    );

    const result = (await containerRes.json()) as {
      label: string;
      score: number;
      logits: { benign: number; malicious: number };
      latency_ms: number;
    };

    const maliciousProb = softmax(result.logits.malicious, result.logits.benign);
    const effectiveLabel = maliciousProb >= threshold ? "MALICIOUS" : "BENIGN";
    const blocked = policy === "block" && effectiveLabel === "MALICIOUS" ? 1 : 0;

    const textHash = await sha256(text);
    this.ctx.storage.sql.exec(
      `INSERT INTO classifications
        (probe_id, phase, text_hash, text_preview, label, score, logit_benign, logit_malicious, threshold, latency_ms, policy, blocked)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      probeId ?? null,
      phase,
      textHash,
      text.slice(0, 100),
      effectiveLabel,
      maliciousProb,
      result.logits.benign,
      result.logits.malicious,
      threshold,
      result.latency_ms,
      policy,
      blocked,
    );

    return {
      label: effectiveLabel,
      score: maliciousProb,
      logits: result.logits,
      latency_ms: result.latency_ms,
      blocked,
    };
  }

  private handleReport(url: URL): Response {
    this.ensureSchema();

    const probeId = url.searchParams.get("probe_id");
    const whereClause = probeId ? "WHERE probe_id = ?" : "";
    const args: string[] = probeId ? [probeId] : [];

    const total = this.ctx.storage.sql
      .exec(`SELECT COUNT(*) as n FROM classifications ${whereClause}`, ...args)
      .one() as { n: number };

    const byLabel = this.ctx.storage.sql
      .exec(
        `SELECT label, COUNT(*) as n FROM classifications ${whereClause} GROUP BY label`,
        ...args,
      )
      .toArray() as { label: string; n: number }[];

    const byPhase = this.ctx.storage.sql
      .exec(
        `SELECT phase, label, COUNT(*) as n FROM classifications ${whereClause} GROUP BY phase, label`,
        ...args,
      )
      .toArray() as { phase: string; label: string; n: number }[];

    const blocked = this.ctx.storage.sql
      .exec(
        `SELECT COUNT(*) as n FROM classifications WHERE blocked = 1 ${probeId ? "AND probe_id = ?" : ""}`,
        ...args,
      )
      .one() as { n: number };

    const avgLatency = this.ctx.storage.sql
      .exec(
        `SELECT AVG(latency_ms) as avg_ms, MIN(latency_ms) as min_ms, MAX(latency_ms) as max_ms FROM classifications ${whereClause}`,
        ...args,
      )
      .one() as { avg_ms: number; min_ms: number; max_ms: number };

    const recentClassifications = this.ctx.storage.sql
      .exec(
        `SELECT probe_id, phase, label, score, latency_ms, text_preview, blocked, ts
         FROM classifications ${whereClause}
         ORDER BY id DESC LIMIT 50`,
        ...args,
      )
      .toArray();

    return json({
      total: total.n,
      by_label: Object.fromEntries(byLabel.map((r) => [r.label, r.n])),
      by_phase: byPhase,
      blocked: blocked.n,
      latency: avgLatency,
      recent: recentClassifications,
    });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const guardId = url.searchParams.get("guard_id") ?? "default";
    const container = getContainer(env.PROMPT_GUARD, guardId);

    url.searchParams.delete("guard_id");
    const cleanRequest = new Request(url.toString(), request);

    return container.fetch(cleanRequest);
  },
};

function softmax(a: number, b: number): number {
  const maxVal = Math.max(a, b);
  const expA = Math.exp(a - maxVal);
  const expB = Math.exp(b - maxVal);
  return expA / (expA + expB);
}

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
