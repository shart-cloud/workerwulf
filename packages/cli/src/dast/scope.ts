import { readFileSync } from "node:fs";

/**
 * Hostname allowlist. Entries are exact hostnames ("app.example.com") or
 * leading-wildcard patterns ("*.example.com", which matches subdomains but not
 * the apex). Optional ":port" pins a port; without one any port matches.
 */
export interface Scope {
  entries: ScopeEntry[];
}

interface ScopeEntry {
  host: string;
  wildcard: boolean;
  port?: string;
}

export function parseScope(lines: string[]): Scope {
  const entries: ScopeEntry[] = [];
  for (const raw of lines) {
    const line = raw.replace(/#.*$/, "").trim().toLowerCase();
    if (!line) continue;
    // Tolerate full URLs in the file — keep only host[:port].
    const hostPort = line.replace(/^[a-z]+:\/\//, "").replace(/\/.*$/, "");
    const [hostPart, port] = hostPort.split(":") as [string, string | undefined];
    const wildcard = hostPart.startsWith("*.");
    const host = wildcard ? hostPart.slice(2) : hostPart;
    if (!host || host.includes("*")) {
      throw new Error(`invalid scope entry "${raw.trim()}" (use host or *.host)`);
    }
    entries.push({ host, wildcard, port });
  }
  return { entries };
}

export function loadScopeFile(path: string): Scope {
  return parseScope(readFileSync(path, "utf8").split(/\r?\n/));
}

export function mergeScopes(...scopes: Scope[]): Scope {
  return { entries: scopes.flatMap((s) => s.entries) };
}

export function inScope(scope: Scope, url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (!["http:", "https:", "ws:", "wss:"].includes(parsed.protocol)) return false;
  const host = parsed.hostname.toLowerCase();
  return scope.entries.some((e) => {
    if (e.port !== undefined && parsed.port !== e.port) return false;
    return e.wildcard ? host.endsWith(`.${e.host}`) : host === e.host;
  });
}
