import { inScope, type Scope } from "./scope.js";

export type ProbeMethod = "GET" | "HEAD" | "OPTIONS" | "POST";

export interface ProbeRequest {
  method?: ProbeMethod;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface ProbeResponse {
  url: string;
  status: number;
  /** Lower-cased header names. Repeated headers are joined with ", ". */
  headers: Record<string, string>;
  /** Response body as text, truncated to MAX_BODY_BYTES. */
  body: string;
  elapsed_ms: number;
}

export interface WsRequest {
  url: string;
  headers?: Record<string, string>;
  /** How long to collect server-sent messages after the upgrade, in ms. */
  listen_ms?: number;
}

export interface WsResult {
  url: string;
  /** True when the server completed the WebSocket upgrade (101). */
  accepted: boolean;
  /** Text frames the server sent during the listen window (each truncated). */
  messages: string[];
  error?: string;
}

/** Transport — real network or a test fake. Never follows redirects. */
export interface HttpClient {
  request(req: ProbeRequest): Promise<ProbeResponse>;
  websocket(req: WsRequest): Promise<WsResult>;
}

export const MAX_BODY_BYTES = 256 * 1024;
const MAX_WS_MESSAGE_BYTES = 8 * 1024;
const MAX_WS_MESSAGES = 16;

export class OutOfScopeError extends Error {
  constructor(url: string) {
    super(`refusing out-of-scope request: ${url}`);
    this.name = "OutOfScopeError";
  }
}

export class BudgetExceededError extends Error {
  constructor(max: number) {
    super(`request budget of ${max} exhausted; remaining checks skipped (raise --max-requests)`);
    this.name = "BudgetExceededError";
  }
}

export interface Exchange {
  method: string;
  url: string;
  status: number | "ws-accepted" | "ws-refused" | "error";
  elapsed_ms: number;
}

export interface ProbeHttpOptions {
  scope: Scope;
  maxRequests: number;
  /** Requests per second; Infinity disables pacing (tests). */
  rps: number;
}

/**
 * The only client probe rules see. Enforces the scope allowlist on every
 * request (including WebSockets), paces requests to `rps`, stops at
 * `maxRequests`, and records a transcript for the report.
 */
export class ProbeHttp {
  readonly transcript: Exchange[] = [];
  private nextSlot = 0;

  constructor(
    private readonly inner: HttpClient,
    private readonly opts: ProbeHttpOptions,
  ) {}

  get used(): number {
    return this.transcript.length;
  }

  async request(req: ProbeRequest): Promise<ProbeResponse> {
    await this.admit(req.url);
    const method = req.method ?? "GET";
    try {
      const res = await this.inner.request({ ...req, method });
      this.transcript.push({ method, url: req.url, status: res.status, elapsed_ms: res.elapsed_ms });
      return res;
    } catch (err) {
      this.transcript.push({ method, url: req.url, status: "error", elapsed_ms: 0 });
      throw err;
    }
  }

  /** GET with in-scope redirect following (at most `max` hops). */
  async follow(req: ProbeRequest, max = 3): Promise<ProbeResponse> {
    let res = await this.request(req);
    for (let hop = 0; hop < max; hop++) {
      const location = res.headers["location"];
      if (res.status < 300 || res.status >= 400 || !location) return res;
      const next = new URL(location, res.url).toString();
      if (!inScope(this.opts.scope, next)) return res;
      res = await this.request({ ...req, url: next, method: "GET", body: undefined });
    }
    return res;
  }

  async websocket(req: WsRequest): Promise<WsResult> {
    await this.admit(req.url);
    const res = await this.inner.websocket(req);
    this.transcript.push({
      method: "WS",
      url: req.url,
      status: res.error && !res.accepted ? "error" : res.accepted ? "ws-accepted" : "ws-refused",
      elapsed_ms: 0,
    });
    return res;
  }

  private async admit(url: string): Promise<void> {
    if (!inScope(this.opts.scope, url)) throw new OutOfScopeError(url);
    if (this.transcript.length >= this.opts.maxRequests) {
      throw new BudgetExceededError(this.opts.maxRequests);
    }
    if (!Number.isFinite(this.opts.rps) || this.opts.rps <= 0) return;
    const interval = 1000 / this.opts.rps;
    const now = Date.now();
    const wait = this.nextSlot - now;
    this.nextSlot = Math.max(now, this.nextSlot) + interval;
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }
}

function collectHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, name) => {
    const key = name.toLowerCase();
    out[key] = out[key] === undefined ? value : `${out[key]}, ${value}`;
  });
  return out;
}

async function readCapped(res: Response): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < MAX_BODY_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }
  await reader.cancel().catch(() => undefined);
  const buf = Buffer.concat(chunks).subarray(0, MAX_BODY_BYTES);
  return buf.toString("utf8");
}

/** Real transport over Node's global fetch / WebSocket (Node ≥ 22). */
export class FetchHttpClient implements HttpClient {
  constructor(
    private readonly timeoutMs: number,
    private readonly userAgent: string,
  ) {}

  async request(req: ProbeRequest): Promise<ProbeResponse> {
    const started = Date.now();
    const res = await fetch(req.url, {
      method: req.method ?? "GET",
      headers: { "user-agent": this.userAgent, ...req.headers },
      body: req.body,
      redirect: "manual",
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const body = req.method === "HEAD" ? "" : await readCapped(res);
    return {
      url: req.url,
      status: res.status,
      headers: collectHeaders(res.headers),
      body,
      elapsed_ms: Date.now() - started,
    };
  }

  websocket(req: WsRequest): Promise<WsResult> {
    const Ctor = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
    if (!Ctor) {
      return Promise.resolve({
        url: req.url,
        accepted: false,
        messages: [],
        error: "WebSocket unavailable in this Node.js runtime (need Node ≥ 22)",
      });
    }
    const wsUrl = req.url.replace(/^http/, "ws");
    const listenMs = req.listen_ms ?? 1500;
    return new Promise((resolve) => {
      const messages: string[] = [];
      let accepted = false;
      let settled = false;
      // undici's WebSocket accepts a non-standard `{ headers }` init.
      const init = { headers: { "user-agent": this.userAgent, ...req.headers } };
      const ws = new (Ctor as unknown as new (url: string, init: unknown) => WebSocket)(wsUrl, init);
      const finish = (error?: string): void => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        try {
          ws.close();
        } catch {
          // already closed
        }
        resolve({ url: req.url, accepted, messages, error });
      };
      const deadline = setTimeout(() => finish(accepted ? undefined : "timeout"), this.timeoutMs);
      ws.addEventListener("open", () => {
        accepted = true;
        setTimeout(() => finish(), listenMs);
      });
      ws.addEventListener("message", (ev: MessageEvent) => {
        if (messages.length >= MAX_WS_MESSAGES) return;
        const text = typeof ev.data === "string" ? ev.data : "[binary frame]";
        messages.push(text.slice(0, MAX_WS_MESSAGE_BYTES));
      });
      ws.addEventListener("error", () => finish(accepted ? undefined : "upgrade refused"));
      ws.addEventListener("close", () => finish());
    });
  }
}
