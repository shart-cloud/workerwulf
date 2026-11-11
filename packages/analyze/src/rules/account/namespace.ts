import { registerAccount, type Finding } from "../../engine/rule.js";

/**
 * Workers-for-Platforms namespace posture, read live from the API (the gaps the
 * offline WF-WFP-* rules can't see). Namespace introspection depends on account
 * API capabilities; missing fields degrade to no-finding rather than a false
 * claim.
 */

registerAccount({
  id: "WF-NS-01",
  title: "WfP dispatch namespace in trusted mode",
  severity: "high",
  probe: "P-TEN-*",
  family: "G",
  check(ctx) {
    const findings: Finding[] = [];
    for (const ns of ctx.namespaces) {
      if (!ns.trusted) continue;
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `namespace:${ns.name}`,
        message:
          `Dispatch namespace "${ns.name}" runs in trusted mode. Trusted tenant Workers get the ` +
          "platform's authority instead of being sandboxed. P-TEN-* demonstrated cross-tenant " +
          "isolation breaks when user code runs trusted.",
        remediation: "Run tenant dispatch namespaces in untrusted mode.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

registerAccount({
  id: "WF-NS-02",
  title: "WfP dispatch namespace without an outbound worker",
  severity: "high",
  probe: "F-002",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const ns of ctx.namespaces) {
      if (ns.hasOutbound) continue;
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `namespace:${ns.name}`,
        message:
          `Dispatch namespace "${ns.name}" has no outbound worker. Dispatched tenant Workers can ` +
          "then make arbitrary outbound fetches. F-002 demonstrated unrestricted egress (data " +
          "exfil, attacker callbacks) without an outbound worker mediating network access.",
        remediation:
          "Configure an outbound worker on the namespace that enforces an egress allowlist for " +
          "dispatched Workers.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

registerAccount({
  id: "WF-NS-03",
  title: "WfP dispatch namespace without custom limits",
  severity: "medium",
  probe: "P-LIM-*",
  family: "F",
  check(ctx) {
    const findings: Finding[] = [];
    for (const ns of ctx.namespaces) {
      if (ns.hasLimits) continue;
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `namespace:${ns.name}`,
        message:
          `Dispatch namespace "${ns.name}" has no custom limits (cpuMs, subRequests). P-LIM-* ` +
          "demonstrated a tenant Worker can consume the platform's CPU/subrequest budget without " +
          "per-dispatch limits (resource exhaustion / noisy neighbor).",
        remediation:
          "Set custom limits at dispatch time (cpuMs, subRequests) so one tenant cannot exhaust " +
          "shared resources.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

registerAccount({
  id: "WF-NS-04",
  title: "WfP namespace has scripts not in untrusted mode",
  severity: "medium",
  probe: "P-DISP-*",
  family: "G",
  check(ctx) {
    const findings: Finding[] = [];
    for (const ns of ctx.namespaces) {
      const notUntrusted = ns.scripts.filter((s) => !s.untrusted);
      if (notUntrusted.length === 0) continue;
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `namespace:${ns.name}`,
        message:
          `Dispatch namespace "${ns.name}" contains script(s) not explicitly in untrusted mode ` +
          `(${notUntrusted.map((s) => s.name).join(", ")}). P-DISP-* showed dispatched scripts ` +
          "should run untrusted so a compromised tenant Worker stays sandboxed.",
        remediation:
          "Dispatch tenant scripts in untrusted mode; reserve trusted mode for first-party platform " +
          "code only.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});
