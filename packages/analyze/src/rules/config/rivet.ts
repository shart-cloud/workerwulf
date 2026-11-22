import { registerConfig, type Finding } from "../../engine/rule.js";

/**
 * Secrets that OpenOrange / Rivet production checklists explicitly warn must
 * never be placed in Wrangler `vars` (which are baked into the container image
 * by `orange deploy` and readable from config/state):
 *   - RIVET_ENDPOINT embeds an Engine token in the URL (`https://ns:token@host`).
 *   - RIVET_TOKEN / RIVET_CLOUD_TOKEN grant Rivet Engine / Cloud API access.
 *   - WORKER_MIGRATOR_TOKEN authenticates `/__migrate/*` and `/__migrate-d1/*`.
 *   - OTEL_EXPORTER_OTLP_HEADERS commonly carries collector API keys.
 */
const RIVET_SECRET_VARS = new Set([
  "RIVET_ENDPOINT",
  "RIVET_TOKEN",
  "RIVET_CLOUD_TOKEN",
  "WORKER_MIGRATOR_TOKEN",
  "OTEL_EXPORTER_OTLP_HEADERS",
]);

registerConfig({
  id: "WF-RIVET-01",
  title: "Rivet / OpenOrange credential or token-bearing endpoint in Wrangler vars",
  severity: "critical",
  probe: "W-CAP-02",
  family: "A",
  check(ctx) {
    const vars = ctx.config.vars;
    if (!vars || typeof vars !== "object") return [];
    const findings: Finding[] = [];
    for (const [key, value] of Object.entries(vars)) {
      if (!RIVET_SECRET_VARS.has(key)) continue;
      if (typeof value !== "string" || value.trim().length === 0) continue;
      // Plain http(s) RIVET_ENDPOINT without userinfo (`user:pass@`) is lower risk
      // than an embedded-token URL, though still flagged if it contains credentials.
      const isEndpoint = key === "RIVET_ENDPOINT";
      const hasEmbeddedCreds = /^https?:\/\/[^/\s:@]+:[^/\s@]+@/i.test(value);
      if (isEndpoint && !hasEmbeddedCreds) continue;
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:vars.${key}`,
        message:
          `Wrangler var "${key}" contains a Rivet / OpenOrange credential` +
          (isEndpoint ? " embedded in the Engine endpoint URL" : "") +
          ". OpenOrange bakes `vars` into the deployed container image (and Cloudflare stores them " +
          "as plaintext config), exposing Rivet Engine / actor-gateway access to anyone who can " +
          "read the repo, image, or deployment config.",
        remediation:
          `Remove "${key}" from wrangler vars and supply it out-of-band as a runtime secret ` +
          "(`orange deploy --secret` / `--secrets-file`, container secret env, or `wrangler secret put`). " +
          "Rotate the exposed token immediately.",
        probe: this.probe,
        family: this.family,
        evidence: [{ type: "config", label: `vars.${key}`, inline: `${key}=<redacted ${value.length} chars>` }],
      });
    }
    return findings;
  },
});

registerConfig({
  id: "WF-RIVET-02",
  title: "OpenOrange live-migration setting left in Wrangler vars",
  severity: "high",
  probe: "D-DO-*",
  family: "E",
  check(ctx) {
    const vars = ctx.config.vars;
    if (!vars || typeof vars !== "object") return [];
    const url = vars["ORANGE_MIGRATE_WORKER_URL"];
    if (typeof url !== "string" || url.trim().length === 0) return [];
    return [
      {
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:vars.ORANGE_MIGRATE_WORKER_URL`,
        message:
          'Wrangler var "ORANGE_MIGRATE_WORKER_URL" is set in config. While this setting is active, ' +
          "OpenOrange mounts internal migration routes (`/__migrate/*`, `/__migrate-d1/*`) ahead of " +
          "the Worker handler and lazily imports Durable Object / D1 state from the migration source.",
        remediation:
          "Remove ORANGE_MIGRATE_WORKER_URL and WORKER_MIGRATOR_TOKEN after cutover is complete so " +
          "internal migration routes are disabled in production.",
        probe: this.probe,
        family: this.family,
        evidence: [{ type: "config", label: "vars.ORANGE_MIGRATE_WORKER_URL", inline: url.slice(0, 120) }],
      },
    ];
  },
});
