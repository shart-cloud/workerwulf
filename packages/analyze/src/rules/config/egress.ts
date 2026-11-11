import { registerConfig, type Finding } from "../../engine/rule.js";
import type { BindingEntry } from "../../parsers/wrangler.js";

registerConfig({
  id: "WF-EGR-01",
  title: "WfP dispatch namespace without an outbound worker",
  severity: "high",
  probe: "F-002",
  family: "E",
  check(ctx) {
    const namespaces = ctx.config.dispatch_namespaces ?? [];
    const findings: Finding[] = [];
    namespaces.forEach((ns: BindingEntry, i) => {
      if (ns["outbound"]) return; // outbound worker configured — OK
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:dispatch_namespaces[${i}]`,
        message:
          `Dispatch namespace binding "${ns.binding ?? ns.name ?? "(unnamed)"}" has no outbound ` +
          "worker configured. Without an outbound worker, user/tenant Workers dispatched into the " +
          "namespace can make arbitrary outbound fetches. F-002 demonstrated unrestricted egress " +
          "(data exfil, callback to attacker infrastructure) when no outbound worker mediates the " +
          "dispatched Worker's network access.",
        remediation:
          "Configure an outbound worker on the dispatch namespace (the `outbound` field) that " +
          "enforces an egress allowlist for dispatched Workers.",
        probe: this.probe,
        family: this.family,
        evidence: [{ type: "config", label: "dispatch_namespace", inline: JSON.stringify(ns) }],
      });
    });
    return findings;
  },
});

registerConfig({
  id: "WF-EGR-02",
  title: "Dynamic Worker loader without a constrained globalOutbound",
  severity: "medium",
  probe: "D-NET-01",
  family: "E",
  check(ctx) {
    // Worker Loader bindings let a Worker load and run dynamic code. Without
    // globalOutbound:null (set at load time in source), the loaded code inherits
    // unrestricted egress. Config-level we can only flag the binding's presence;
    // the source rule set verifies the globalOutbound argument in Phase 2.
    const loaders = (ctx.config["worker_loaders"] as BindingEntry[] | undefined) ?? [];
    if (loaders.length === 0) return [];
    return loaders.map((l, i) => ({
      rule_id: this.id,
      title: this.title,
      severity: this.severity,
      resource: `${ctx.configPath}:worker_loaders[${i}]`,
      message:
        `Worker Loader binding "${l.binding ?? l.name ?? "(unnamed)"}" is declared. Dynamically ` +
        "loaded Workers inherit unrestricted outbound network access unless the loader is invoked " +
        "with globalOutbound:null (or a constraining outbound worker). D-NET-01 demonstrated egress " +
        "from dynamically loaded code when globalOutbound was left at its default.",
      remediation:
        "When invoking the loader, pass `globalOutbound: null` (or a dedicated outbound worker) so " +
        "the dynamically loaded Worker cannot make arbitrary outbound requests.",
      probe: this.probe,
      family: this.family,
      evidence: [{ type: "config", label: "worker_loader", inline: JSON.stringify(l) }],
    }));
  },
});
