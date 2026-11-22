import { registerConfig, type Finding } from "../../engine/rule.js";
import type { WranglerConfig } from "../../parsers/wrangler.js";

interface CacheConfigEntry {
  location: string;
  enabled: boolean;
  crossVersion: boolean;
}

export function enabledWorkersCaches(config: WranglerConfig): CacheConfigEntry[] {
  const out: CacheConfigEntry[] = [];
  const top = config["cache"] as { enabled?: unknown; cross_version_cache?: unknown } | undefined;
  if (top && typeof top === "object" && top.enabled === true) {
    out.push({
      location: "cache",
      enabled: true,
      crossVersion: top.cross_version_cache === true,
    });
  }
  const exportsMap = config["exports"] as Record<string, { cache?: { enabled?: unknown; cross_version_cache?: unknown } }> | undefined;
  if (exportsMap && typeof exportsMap === "object") {
    for (const [name, entry] of Object.entries(exportsMap)) {
      const c = entry?.cache;
      if (c && typeof c === "object" && c.enabled === true) {
        out.push({
          location: `exports.${name}.cache`,
          enabled: true,
          crossVersion: c.cross_version_cache === true,
        });
      }
    }
  }
  return out;
}

/**
 * WF-WC-01 — Wave 5 (W-WC-03/04/05). Declarative Workers Cache (`ctx.cache`)
 * enabled in Wrangler config. Custom auth headers are NOT part of the cache key
 * (only path + entrypoint + ctx.props + version); `cross_version_cache: true`
 * additionally allows poisoned entries to persist across deploys.
 */
registerConfig({
  id: "WF-WC-01",
  title: "Declarative Workers Cache enabled — verify ctx.props keying and version isolation",
  severity: "medium",
  probe: "W-WC-04",
  family: "C",
  check(ctx) {
    const entries = enabledWorkersCaches(ctx.config);
    if (entries.length === 0) return [];
    const findings: Finding[] = [];
    for (const entry of entries) {
      const high = entry.crossVersion;
      findings.push({
        rule_id: this.id,
        title: high
          ? "Declarative Workers Cache enabled with cross_version_cache"
          : this.title,
        severity: high ? "high" : this.severity,
        resource: `${ctx.configPath}:${entry.location}`,
        message:
          `Workers Cache is enabled at "${entry.location}". ` +
          (high
            ? "`cross_version_cache = true` keeps cached entries alive across Worker deployments, allowing a poisoned or leaked entry to outlive a security fix. "
            : "") +
          "W-WC-03/04 demonstrated that Workers Cache keys only on path, entrypoint, `ctx.props`, and Worker version — custom auth/identity headers are unkeyed and cause cross-caller response leaks.",
        remediation:
          "Key every personalized response through `ctx.props` (or disable caching on authenticated entrypoints with `Cache-Control: private, no-store`), keep `cross_version_cache = false`, and enable caching per-entrypoint rather than globally.",
        probe: this.probe,
        family: this.family,
        evidence: [{ type: "config", label: entry.location, inline: JSON.stringify(entry) }],
      });
    }
    return findings;
  },
});
