import type { ProbeResponse } from "../../dast/http.js";
import { registerProbe, type Finding, type Severity } from "../../engine/rule.js";
import { excerpt, httpEvidence, isHtml, isSoft404, probeFinding, redactEnv, sameOriginUrl } from "./_utils.js";

/**
 * Workers Static Assets uploads everything under `assets.directory`. Pointing
 * it at the project root (or a build dir that copies dotfiles) publishes local
 * secrets, wrangler config and Worker source as static files — served before
 * the Worker runs, so no route code can protect them.
 */
interface ExposureCheck {
  path: string;
  /** Content validator — proves the file is real, not a catch-all page. */
  matches: (r: ProbeResponse) => boolean;
  severity: Severity;
  what: string;
  redact?: boolean;
}

const ENV_LINE = /^\s*(?:export\s+)?[A-Z_][A-Z0-9_]*\s*=\s*\S/m;
const WRANGLER_TOML = /^\s*(compatibility_date|main|account_id)\s*=/m;
const WRANGLER_JSON = /"compatibility_date"\s*:/;
const WORKER_SOURCE = /export\s+default\b[\s\S]{0,4000}\bfetch\s*\(/;

const SECRET_FILES: ExposureCheck[] = [
  { path: "/.dev.vars", matches: (r) => ENV_LINE.test(r.body), severity: "critical", what: "wrangler local secrets file (.dev.vars)", redact: true },
  { path: "/.dev.vars.production", matches: (r) => ENV_LINE.test(r.body), severity: "critical", what: "wrangler per-env secrets file", redact: true },
  { path: "/.env", matches: (r) => ENV_LINE.test(r.body), severity: "critical", what: ".env secrets file", redact: true },
  { path: "/.env.local", matches: (r) => ENV_LINE.test(r.body), severity: "critical", what: ".env.local secrets file", redact: true },
  { path: "/.env.production", matches: (r) => ENV_LINE.test(r.body), severity: "critical", what: ".env.production secrets file", redact: true },
  { path: "/.git/HEAD", matches: (r) => /^ref: refs\//.test(r.body), severity: "high", what: "git metadata (.git/ — full history is likely retrievable)" },
];

const CONFIG_FILES: ExposureCheck[] = [
  { path: "/wrangler.toml", matches: (r) => WRANGLER_TOML.test(r.body), severity: "medium", what: "wrangler.toml (binding IDs, routes, account_id)" },
  { path: "/wrangler.json", matches: (r) => WRANGLER_JSON.test(r.body), severity: "medium", what: "wrangler.json (binding IDs, routes, account_id)" },
  { path: "/wrangler.jsonc", matches: (r) => WRANGLER_JSON.test(r.body), severity: "medium", what: "wrangler.jsonc (binding IDs, routes, account_id)" },
  { path: "/.wrangler/deploy/config.json", matches: (r) => /"configPath"/.test(r.body), severity: "medium", what: "wrangler deploy redirect config" },
  { path: "/package.json", matches: (r) => /"(dependencies|devDependencies)"\s*:/.test(r.body), severity: "low", what: "package.json (dependency inventory)" },
];

const SOURCE_FILES: ExposureCheck[] = ["/src/index.ts", "/src/index.js", "/src/worker.ts", "/src/worker.js", "/index.js", "/worker.js", "/_worker.js"].map(
  (path) => ({ path, matches: (r: ProbeResponse) => WORKER_SOURCE.test(r.body) && !isHtml(r), severity: "high" as const, what: "Worker source code" }),
);

function exposureRule(id: string, title: string, severity: Severity, checks: ExposureCheck[]): void {
  registerProbe({
    id,
    title,
    severity,
    probe: "WF-SEC-*",
    family: "DAST",
    async check(ctx) {
      const findings: Finding[] = [];
      for (const c of checks) {
        const url = sameOriginUrl(ctx, c.path);
        const res = await ctx.http.request({ url });
        if (res.status !== 200 || isSoft404(res, ctx.fingerprint) || !c.matches(res)) continue;
        const shown = c.redact ? redactEnv(res.body) : res.body;
        findings.push(
          probeFinding(
            this,
            url,
            `${c.what} is publicly downloadable at ${c.path}.${c.redact ? " Values were redacted from this report; rotate every credential in the file." : ""}`,
            "Point `assets.directory` at a dedicated build-output folder (never the project root), add an `.assetsignore` covering dotfiles, wrangler config and src/, and rotate anything that was exposed.",
            [httpEvidence(c.path, res, { body: excerpt(shown, 600) })],
            c.severity,
          ),
        );
      }
      return findings;
    },
  });
}

exposureRule("WF-DAST-EXPOSE-01", "Secrets file served as a static asset", "critical", SECRET_FILES);
exposureRule("WF-DAST-EXPOSE-02", "Wrangler/project config served as a static asset", "medium", CONFIG_FILES);
exposureRule("WF-DAST-EXPOSE-03", "Worker source served as a static asset", "high", SOURCE_FILES);

registerProbe({
  id: "WF-DAST-EXPOSE-04",
  title: "Production source maps published",
  severity: "low",
  probe: "WF-SEC-*",
  family: "DAST",
  async check(ctx) {
    const base = ctx.fingerprint.baseline;
    if (!isHtml(base)) return [];
    const scripts = [...base.body.matchAll(/<script[^>]+src=["']([^"']+\.m?js)(?:\?[^"']*)?["']/gi)]
      .map((m) => m[1]!)
      .map((src) => new URL(src, base.url))
      .filter((u) => u.origin === ctx.target.origin)
      .slice(0, 5);
    const findings: Finding[] = [];
    for (const script of scripts) {
      const url = `${script.origin}${script.pathname}.map`;
      const res = await ctx.http.request({ url });
      if (res.status !== 200 || !/"mappings"\s*:/.test(res.body) || !/"sources"\s*:/.test(res.body)) continue;
      const withContent = /"sourcesContent"\s*:\s*\[\s*"/.test(res.body);
      findings.push(
        probeFinding(
          this,
          url,
          `Source map for ${script.pathname} is public${withContent ? " and embeds full original source (sourcesContent)" : ""}.`,
          "Stop emitting source maps for production assets, or upload them to your error tracker and exclude `*.map` via `.assetsignore`.",
          [httpEvidence("source map", res, { body: excerpt(res.body, 200) })],
          withContent ? "medium" : "low",
        ),
      );
    }
    return findings;
  },
});
