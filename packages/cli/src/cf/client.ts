import type { BindingType, DeclaredBinding } from "../parsers/bindings.js";

/** Raw binding entry from the Cloudflare API (script settings). */
export interface RawBinding {
  type: string;
  name: string;
  [key: string]: unknown;
}

/** Normalized dispatch-namespace data from the API. */
export interface RawNamespace {
  name: string;
  trusted?: boolean;
  outbound?: unknown;
  limits?: unknown;
  scripts?: { name: string; untrusted?: boolean }[];
}

/**
 * The Cloudflare surface the scanner needs. Defined as an interface so the
 * account rules and `wulf scan` orchestration can be tested offline with a fake
 * client — the live `RestCfClient` is just one implementation.
 */
export interface CfClient {
  listScripts(): Promise<string[]>;
  getScriptBindings(scriptName: string): Promise<RawBinding[]>;
  getScriptContent(scriptName: string): Promise<string | undefined>;
  getRoutes(scriptName: string): Promise<string[]>;
  listNamespaces(): Promise<string[]>;
  getNamespace(name: string): Promise<RawNamespace | undefined>;
}

/**
 * Map a Cloudflare API binding `type` to a capability BindingType. Returns
 * undefined for non-capability bindings (plain_text, json, wasm_module, ...),
 * which carry no blast radius.
 */
const API_BINDING_TYPES: Record<string, BindingType> = {
  kv_namespace: "kv_namespace",
  r2_bucket: "r2_bucket",
  d1: "d1_database",
  d1_database: "d1_database",
  hyperdrive: "hyperdrive",
  service: "service",
  queue: "queue_producer",
  browser: "browser",
  browser_rendering: "browser",
  ai: "ai",
  vectorize: "vectorize",
  mtls_certificate: "mtls_certificate",
  send_email: "send_email",
  analytics_engine: "analytics_engine",
  secret_text: "secret",
  secrets_store_secret: "secret",
  dispatch_namespace: "dispatch_namespace",
  durable_object_namespace: "durable_object",
};

export function mapApiBinding(raw: RawBinding): DeclaredBinding | undefined {
  const type = API_BINDING_TYPES[raw.type];
  if (!type) return undefined;
  return { type, name: raw.name, configKey: `binding:${raw.name}` };
}

const DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4";

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

interface CfEnvelope<T> {
  result: T;
  success: boolean;
  errors?: { message: string }[];
}

/**
 * Thin REST client over the Cloudflare API. Best-effort: namespace introspection
 * (trusted mode, outbound, limits) and per-script routes depend on the account's
 * API capabilities and may be unavailable — those methods degrade to empty/false
 * rather than throwing, and the corresponding findings document the limitation.
 */
export class RestCfClient implements CfClient {
  private readonly accountId: string;
  private readonly token: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(opts: {
    accountId: string;
    token: string;
    baseUrl?: string;
    fetchImpl?: FetchLike;
  }) {
    this.accountId = opts.accountId;
    this.token = opts.token;
    this.baseUrl = opts.baseUrl ?? DEFAULT_BASE_URL;
    this.fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
  }

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      headers: { Authorization: `Bearer ${this.token}`, Accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`Cloudflare API ${path} returned ${res.status} ${res.statusText}`);
    }
    const body = (await res.json()) as CfEnvelope<T>;
    if (body.success === false) {
      const msg = body.errors?.map((e) => e.message).join("; ") ?? "unknown error";
      throw new Error(`Cloudflare API ${path} failed: ${msg}`);
    }
    return body.result;
  }

  private async getOptional<T>(path: string): Promise<T | undefined> {
    try {
      return await this.get<T>(path);
    } catch {
      return undefined;
    }
  }

  private acct(): string {
    return `/accounts/${this.accountId}`;
  }

  async listScripts(): Promise<string[]> {
    const scripts = await this.get<{ id: string }[]>(`${this.acct()}/workers/scripts`);
    return scripts.map((s) => s.id);
  }

  async getScriptBindings(scriptName: string): Promise<RawBinding[]> {
    const settings = await this.getOptional<{ bindings?: RawBinding[] }>(
      `${this.acct()}/workers/scripts/${scriptName}/settings`,
    );
    return settings?.bindings ?? [];
  }

  async getScriptContent(scriptName: string): Promise<string | undefined> {
    const res = await this.fetchImpl(
      `${this.baseUrl}${this.acct()}/workers/scripts/${scriptName}/content`,
      { headers: { Authorization: `Bearer ${this.token}` } },
    );
    if (!res.ok) return undefined;
    const contentType = res.headers.get("content-type") ?? "";
    const text = await res.text();
    return contentType.includes("multipart/") ? extractModulesJs(text) : text;
  }

  async getRoutes(scriptName: string): Promise<string[]> {
    const routes = await this.getOptional<{ pattern?: string }[]>(
      `${this.acct()}/workers/scripts/${scriptName}/routes`,
    );
    return (routes ?? []).map((r) => r.pattern).filter((p): p is string => Boolean(p));
  }

  async listNamespaces(): Promise<string[]> {
    const namespaces = await this.getOptional<{ namespace_name?: string }[]>(
      `${this.acct()}/workers/dispatch/namespaces`,
    );
    return (namespaces ?? [])
      .map((n) => n.namespace_name)
      .filter((n): n is string => Boolean(n));
  }

  async getNamespace(name: string): Promise<RawNamespace | undefined> {
    const ns = await this.getOptional<Record<string, unknown>>(
      `${this.acct()}/workers/dispatch/namespaces/${name}`,
    );
    if (!ns) return undefined;
    return {
      name,
      trusted: ns["trusted_workers"] === true || ns["trusted"] === true,
      outbound: ns["outbound"],
      limits: ns["limits"],
      scripts: undefined,
    };
  }
}

/**
 * Best-effort extraction of JS from a multipart module-worker content response.
 * Strips multipart headers and concatenates body segments — good enough for the
 * binding map's env.X scan across the bundle (PRD §12.1 limitation).
 */
function extractModulesJs(multipart: string): string {
  const boundaryMatch = multipart.match(/^--(\S+)/m);
  if (!boundaryMatch) return multipart;
  const boundary = `--${boundaryMatch[1]}`;
  return multipart
    .split(boundary)
    .map((part) => {
      const sep = part.indexOf("\r\n\r\n");
      return sep >= 0 ? part.slice(sep + 4) : "";
    })
    .join("\n");
}
