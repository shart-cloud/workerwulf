import { registerConfig } from "../../engine/rule.js";

const SIX_MONTHS_MS = 1000 * 60 * 60 * 24 * 182;

registerConfig({
  id: "WF-CFG-01",
  title: "nodejs_compat exposes process.env as a second secret enumeration path",
  severity: "medium",
  probe: "W-CFG-05",
  family: "G",
  check(ctx) {
    const flags = ctx.config.compatibility_flags ?? [];
    if (!flags.includes("nodejs_compat")) return [];
    return [
      {
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:compatibility_flags`,
        message:
          "nodejs_compat injects Node.js globals (Buffer, process, global, setImmediate) and " +
          "surfaces every [vars] entry through process.env — a second config/secret enumeration " +
          "path that does not exist without the flag. W-CFG-05 confirmed 5 globals + 3 vars via " +
          "process.env with the flag on vs zero surface with it off.",
        remediation:
          "Remove nodejs_compat if not required. If required, audit all [vars] entries as if they " +
          "were environment variables readable by any code path in the Worker.",
        probe: this.probe,
        family: this.family,
        evidence: [
          {
            type: "config",
            label: "compatibility_flags",
            inline: JSON.stringify(flags),
          },
        ],
      },
    ];
  },
});

registerConfig({
  id: "WF-CFG-02",
  title: "Missing or stale compatibility_date",
  severity: "informational",
  probe: "W-ENV-03",
  family: "G",
  check(ctx) {
    const date = ctx.config.compatibility_date;
    if (!date) {
      return [
        {
          rule_id: this.id,
          title: this.title,
          severity: this.severity,
          resource: `${ctx.configPath}:compatibility_date`,
          message:
            "No compatibility_date is set. The Workers runtime then pins behavior to an implicit " +
            "default that can shift the runtime's security and API surface unpredictably between " +
            "deploys.",
          remediation:
            "Set an explicit compatibility_date to a recent date so runtime behavior is pinned and " +
            "auditable.",
          probe: this.probe,
          family: this.family,
        },
      ];
    }
    const parsed = Date.parse(date);
    if (Number.isNaN(parsed)) return [];
    if (Date.now() - parsed <= SIX_MONTHS_MS) return [];
    return [
      {
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:compatibility_date`,
        message:
          `compatibility_date "${date}" is more than 6 months old. Stale dates miss runtime ` +
          "hardening and behavior changes shipped since, widening the effective attack surface.",
        remediation:
          "Bump compatibility_date to a recent value and re-test. Review the Workers compatibility " +
          "flags changelog for behavior changes since the current date.",
        probe: this.probe,
        family: this.family,
        evidence: [{ type: "config", label: "compatibility_date", inline: date }],
      },
    ];
  },
});
