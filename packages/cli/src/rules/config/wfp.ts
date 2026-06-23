import { registerConfig, type Finding } from "../../engine/rule.js";
import type { BindingEntry } from "../../parsers/wrangler.js";

/**
 * Workers-for-Platforms namespace posture (PRD §9.4). Much WfP configuration
 * (trusted mode, per-dispatch custom limits) lives in the Cloudflare API rather
 * than wrangler.toml — `wulf scan` (Phase 3) checks the live namespace. These
 * offline rules catch the cases that *are* expressible in config.
 */

function isTrusted(obj: Record<string, unknown>): boolean {
  return obj["trusted_workers"] === true;
}

registerConfig({
  id: "WF-WFP-01",
  title: "Workers-for-Platforms namespace in trusted mode",
  severity: "high",
  probe: "P-TEN-*",
  family: "G",
  check(ctx) {
    const findings: Finding[] = [];
    // trusted_workers can sit at top level or on an individual namespace entry.
    if (isTrusted(ctx.config as Record<string, unknown>)) {
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:trusted_workers`,
        message:
          "trusted_workers = true places dispatched tenant Workers in trusted mode, granting them " +
          "the platform's authority instead of sandboxing them. P-TEN-* demonstrated cross-tenant " +
          "isolation breaks when user code runs trusted.",
        remediation:
          "Set trusted_workers = false (untrusted mode) for any namespace that dispatches " +
          "third-party / tenant code.",
        probe: this.probe,
        family: this.family,
      });
    }
    (ctx.config.dispatch_namespaces ?? []).forEach((ns: BindingEntry, i) => {
      if (isTrusted(ns)) {
        findings.push({
          rule_id: this.id,
          title: this.title,
          severity: this.severity,
          resource: `${ctx.configPath}:dispatch_namespaces[${i}]`,
          message:
            `Dispatch namespace "${ns.binding ?? ns.name ?? "(unnamed)"}" is configured with ` +
            "trusted_workers = true. P-TEN-* demonstrated that trusted-mode tenant code breaks " +
            "multi-tenant isolation.",
          remediation:
            "Run tenant dispatch namespaces in untrusted mode (trusted_workers = false).",
          probe: this.probe,
          family: this.family,
        });
      }
    });
    return findings;
  },
});

registerConfig({
  id: "WF-WFP-02",
  title: "Workers-for-Platforms dispatch without custom limits",
  severity: "medium",
  probe: "P-LIM-*",
  family: "F",
  check(ctx) {
    const namespaces = ctx.config.dispatch_namespaces ?? [];
    if (namespaces.length === 0) return [];
    if (ctx.config["limits"]) return []; // some custom limits declared
    return [
      {
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:dispatch_namespaces`,
        message:
          "Dispatch namespace(s) are declared but no custom limits (cpuMs, subRequests) are set. " +
          "P-LIM-* demonstrated that without per-dispatch limits a tenant Worker can consume the " +
          "platform's CPU/subrequest budget (resource-exhaustion / noisy-neighbor).",
        remediation:
          "Pass custom limits (cpuMs, subRequests) at dispatch time, or configure namespace-level " +
          "limits, so a single tenant Worker cannot exhaust shared resources.",
        probe: this.probe,
        family: this.family,
      },
    ];
  },
});
