import { registerProbe } from "../../engine/rule.js";
import { probeFinding } from "./_utils.js";

registerProbe({
  id: "WF-DAST-FP-01",
  title: "Platform fingerprint",
  severity: "informational",
  probe: "W-RUN-*",
  family: "DAST",
  async check(ctx) {
    const fp = ctx.fingerprint;
    const parts = [
      `Platform: ${fp.platform} (${fp.confidence} confidence).`,
      fp.colo ? `Colo: ${fp.colo}.` : "",
      fp.frameworks.length ? `Frameworks: ${fp.frameworks.join(", ")}.` : "",
      fp.features.smart_placement ? `Smart Placement: ${fp.features.smart_placement}.` : "",
      fp.features.static_assets ? "Baseline served by Workers Static Assets (likely)." : "",
    ].filter(Boolean);
    return [
      probeFinding(
        this,
        fp.target,
        parts.join(" "),
        "None — informational. Signals are listed as evidence so the verdict can be audited.",
        fp.signals.map((s) => ({
          type: "http" as const,
          label: `${s.id} → ${s.points_to} (+${s.weight})`,
          inline: s.detail,
        })),
      ),
    ];
  },
});

registerProbe({
  id: "WF-DAST-ACCESS-01",
  title: "Cloudflare Access gate — verify alternate routes are closed",
  severity: "informational",
  probe: "WF-CFG-*",
  family: "DAST",
  async check(ctx) {
    const fp = ctx.fingerprint;
    if (!fp.features.access_protected) return [];
    return [
      probeFinding(
        this,
        fp.target,
        "This hostname is gated by Cloudflare Access. An Access application protects a hostname, not a Worker: the same script stays reachable on its workers.dev route and on preview URLs unless those are disabled.",
        'Set `workers_dev = false` and `preview_urls = false` in wrangler config for Access-gated Workers (or put those hostnames behind Access too), and validate the Cf-Access-Jwt-Assertion in the Worker rather than trusting the edge alone.',
        [{ type: "http", label: "baseline redirect", inline: fp.baseline.headers["location"] ?? "" }],
      ),
    ];
  },
});
