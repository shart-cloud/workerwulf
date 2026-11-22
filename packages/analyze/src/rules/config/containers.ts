import { registerConfig, type Finding } from "../../engine/rule.js";

/**
 * WF-CTR-01 — Wave 6 (W-CTR-01/04/07). Cloudflare Containers declared on a
 * Worker that does not disable `workers_dev`. Wave 6 showed container processes
 * run as uid 0 with `/proc/1/environ` exposing container secrets and full raw
 * TCP egress; leaving `workers_dev` enabled exposes container-driving routes on
 * a predictable `*.workers.dev` hostname.
 */
registerConfig({
  id: "WF-CTR-01",
  title: "Cloudflare Containers binding on a Worker with workers_dev not disabled",
  severity: "high",
  probe: "W-CTR-01",
  family: "G",
  check(ctx) {
    const containers = ctx.config["containers"] as unknown[] | undefined;
    if (!Array.isArray(containers) || containers.length === 0) return [];
    if (ctx.config["workers_dev"] === false) return [];
    return [
      {
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:containers`,
        message:
          `Worker declares ${containers.length} Cloudflare Container binding(s) without \`workers_dev = false\`. ` +
          "Wave 6 (W-CTR-01/04/05/07) demonstrated that container processes run as uid 0 by default, " +
          "can read Worker-passed container secrets from `/proc/1/environ`, and have raw TCP egress " +
          "beyond isolate `fetch()`. Leaving `workers_dev` enabled exposes the container controller on a public route.",
        remediation:
          "Set `workers_dev = false` (and `preview_urls = false`) for container-owning Workers, require " +
          "explicit authentication on every container-driving route, and pass `enableInternet: false` unless egress is needed.",
        probe: this.probe,
        family: this.family,
        evidence: [{ type: "config", label: "containers", inline: JSON.stringify(containers).slice(0, 200) }],
      },
    ];
  },
});
