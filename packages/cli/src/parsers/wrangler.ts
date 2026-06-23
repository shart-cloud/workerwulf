import { readFileSync } from "node:fs";
import { parse as parseToml } from "smol-toml";

/** A single binding entry. Most use `binding`; send_email/DO use `name`. */
export interface BindingEntry {
  binding?: string;
  name?: string;
  [key: string]: unknown;
}

/**
 * Typed view of a wrangler config. Known fields are modeled; an index signature
 * keeps arbitrary/forward-compatible keys readable by rules. Field shapes follow
 * wrangler.toml / wrangler.json conventions.
 */
export interface WranglerConfig {
  name?: string;
  main?: string;
  compatibility_date?: string;
  compatibility_flags?: string[];

  kv_namespaces?: BindingEntry[];
  r2_buckets?: BindingEntry[];
  d1_databases?: BindingEntry[];
  vectorize?: BindingEntry[];
  hyperdrive?: BindingEntry[];
  services?: BindingEntry[];
  mtls_certificates?: BindingEntry[];
  send_email?: BindingEntry[];
  analytics_engine_datasets?: BindingEntry[];
  secrets_store_secrets?: BindingEntry[];
  dispatch_namespaces?: BindingEntry[];
  queues?: { producers?: BindingEntry[]; consumers?: BindingEntry[] };
  durable_objects?: { bindings?: BindingEntry[] };
  ai?: BindingEntry;
  browser?: BindingEntry;

  vars?: Record<string, unknown>;
  routes?: unknown;
  route?: unknown;

  /** Named environment overrides: [env.production], [env.staging], ... */
  env?: Record<string, WranglerConfig>;

  [key: string]: unknown;
}

export interface ParsedWrangler {
  config: WranglerConfig;
  /** Source format detected from the file extension/content. */
  format: "toml" | "json";
  path: string;
}

/** Strip // line and /* block *\/ comments from JSONC, preserving strings. */
function stripJsonComments(text: string): string {
  let out = "";
  let inString = false;
  let stringQuote = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const next = text[i + 1];
    if (inString) {
      out += ch;
      if (ch === "\\") {
        out += next ?? "";
        i++;
      } else if (ch === stringQuote) {
        inString = false;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = true;
      stringQuote = ch;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++; // land on the closing '/'
      continue;
    }
    out += ch;
  }
  return out;
}

/** Parse a wrangler.toml / wrangler.json / wrangler.jsonc file from disk. */
export function parseWrangler(path: string): ParsedWrangler {
  const text = readFileSync(path, "utf8");
  if (path.endsWith(".toml")) {
    return { config: parseToml(text) as WranglerConfig, format: "toml", path };
  }
  // .json / .jsonc
  const config = JSON.parse(stripJsonComments(text)) as WranglerConfig;
  return { config, format: "json", path };
}

export interface ResolvedEnvironment {
  /** "default" for the base config, otherwise the [env.NAME] name. */
  name: string;
  config: WranglerConfig;
}

/**
 * Resolve each declared environment into its own effective config.
 *
 * Approximation of wrangler's inheritance: an environment inherits the base
 * config, with any keys it redeclares replacing the base value (wrangler does
 * NOT deep-merge binding arrays — a redeclared binding type replaces wholesale).
 * The base config is always returned as "default". `env` itself is stripped from
 * each resolved config so rules don't re-descend into overrides.
 */
export function resolveEnvironments(config: WranglerConfig): ResolvedEnvironment[] {
  const { env, ...base } = config;
  const out: ResolvedEnvironment[] = [{ name: "default", config: base }];
  if (env) {
    for (const [name, override] of Object.entries(env)) {
      const { env: _drop, ...overrideClean } = override;
      out.push({ name, config: { ...base, ...overrideClean } });
    }
  }
  return out;
}
