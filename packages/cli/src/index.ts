import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Command } from "commander";

import { runAudit, type AuditOptions } from "./commands/audit.js";
import { runProbe, type ProbeOptions } from "./commands/probe.js";
import { runReport, type ReportOptions } from "./commands/report.js";
import { runScan, type ScanOptions } from "./commands/scan.js";
import type { Severity } from "./engine/rule.js";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

/** Read the version from package.json — resolves next to src/ (dev) and dist/ (built). */
function readVersion(): string {
  try {
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    return (JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string }).version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const program = new Command();

program
  .name("wulf")
  .description(
    "Cloudflare Workers security scanner — encodes workerwulf research findings " +
      "as static detection rules over wrangler config and Worker source.",
  )
  .version(readVersion());

program
  .command("audit")
  .description("Offline config & source scanning of Cloudflare Workers projects")
  .argument(
    "[paths...]",
    "wrangler.toml files or directories to scan (default: current directory)",
  )
  .option("--source", "also scan Worker source files via oxc-parser AST analysis")
  .option("--strict", "exit 1 on any high/critical finding")
  .option("--json", "output findings as JSON")
  .option("--severity <level>", "minimum severity to report (default: low)")
  .option("--ignore <ids>", "comma-separated rule IDs to suppress")
  .option("--save <dir>", "persist the run report JSON to a directory for `wulf report`")
  .action((paths: string[], opts: Record<string, unknown>) => {
    const severity = opts["severity"] as string | undefined;
    if (severity && !SEVERITIES.includes(severity as Severity)) {
      console.error(`error: invalid --severity "${severity}". Use one of: ${SEVERITIES.join(", ")}`);
      process.exit(2);
    }
    const options: AuditOptions = {
      source: Boolean(opts["source"]),
      strict: Boolean(opts["strict"]),
      json: Boolean(opts["json"]),
      severity: severity as Severity | undefined,
      ignore: opts["ignore"] as string | undefined,
      save: opts["save"] as string | undefined,
    };
    const { output, exitCode } = runAudit(paths, options);
    process.stdout.write(output + "\n");
    process.exit(exitCode);
  });

program
  .command("scan")
  .description("Live Cloudflare account analysis (least-privilege, drift, WfP posture)")
  .option("--account-id <id>", "Cloudflare account ID (or CLOUDFLARE_ACCOUNT_ID)")
  .option("--api-token <tok>", "Cloudflare API token (or CLOUDFLARE_API_TOKEN)")
  .option("--source <dir>", "local source root for drift detection")
  .option("--namespace <name>", "restrict to a specific WfP dispatch namespace")
  .option("--json", "output findings as JSON")
  .option("--strict", "exit 1 on any high/critical finding")
  .option("--severity <level>", "minimum severity to report (default: low)")
  .option("--ignore <ids>", "comma-separated rule IDs to suppress")
  .option("--save <dir>", "persist the run report JSON to a directory for `wulf report`")
  .action(async (opts: Record<string, unknown>) => {
    const severity = opts["severity"] as string | undefined;
    if (severity && !SEVERITIES.includes(severity as Severity)) {
      console.error(`error: invalid --severity "${severity}". Use one of: ${SEVERITIES.join(", ")}`);
      process.exit(2);
    }
    const options: ScanOptions = {
      accountId: opts["accountId"] as string | undefined,
      apiToken: opts["apiToken"] as string | undefined,
      source: opts["source"] as string | undefined,
      namespace: opts["namespace"] as string | undefined,
      json: Boolean(opts["json"]),
      strict: Boolean(opts["strict"]),
      severity: severity as Severity | undefined,
      ignore: opts["ignore"] as string | undefined,
      save: opts["save"] as string | undefined,
    };
    const { output, exitCode } = await runScan(options);
    process.stdout.write(output + "\n");
    process.exit(exitCode);
  });

program
  .command("probe")
  .description("Black-box DAST: fingerprint a live Worker URL and run network vulnerability checks")
  .argument("<url>", "target URL to scan (http/https) — must be in scope")
  .option("--scope <file>", "scope file: one hostname or *.host per line (the target host is always allowed)")
  .option("--allow <hosts>", "comma-separated extra in-scope hosts")
  .option("--paths <paths>", "comma-separated extra same-origin paths to test")
  .option("--passive", "fingerprint only — skip every active vulnerability check")
  .option("--auth-header <header>", '"Name: value" credential for the authenticated cache-leak check')
  .option("--allow-post", "permit POST requests with malformed bodies (off by default)")
  .option("--rps <n>", "max requests per second (default: 5)", (v) => Number(v))
  .option("--max-requests <n>", "hard request budget for the whole run (default: 300)", (v) => Number(v))
  .option("--timeout-ms <n>", "per-request timeout in ms (default: 10000)", (v) => Number(v))
  .option("--json", "output findings as JSON")
  .option("--strict", "exit 1 on any high/critical finding")
  .option("--severity <level>", "minimum severity to report (default: informational)")
  .option("--ignore <ids>", "comma-separated rule IDs to suppress")
  .option("--save <dir>", "persist the run report JSON to a directory for `wulf report`")
  .option("--user-agent <ua>", "override the User-Agent header")
  .action(async (url: string, opts: Record<string, unknown>) => {
    const severity = opts["severity"] as string | undefined;
    if (severity && !SEVERITIES.includes(severity as Severity)) {
      console.error(`error: invalid --severity "${severity}". Use one of: ${SEVERITIES.join(", ")}`);
      process.exit(2);
    }
    const options: ProbeOptions = {
      scope: opts["scope"] as string | undefined,
      allow: opts["allow"] as string | undefined,
      paths: opts["paths"] as string | undefined,
      passive: Boolean(opts["passive"]),
      authHeader: opts["authHeader"] as string | undefined,
      allowPost: Boolean(opts["allowPost"]),
      rps: opts["rps"] as number | undefined,
      maxRequests: opts["maxRequests"] as number | undefined,
      timeoutMs: opts["timeoutMs"] as number | undefined,
      json: Boolean(opts["json"]),
      strict: Boolean(opts["strict"]),
      severity: severity as Severity | undefined,
      ignore: opts["ignore"] as string | undefined,
      save: opts["save"] as string | undefined,
      userAgent: opts["userAgent"] as string | undefined,
    };
    const { output, exitCode } = await runProbe(url, options);
    process.stdout.write(output + "\n");
    process.exit(exitCode);
  });

program
  .command("report")
  .description("Aggregate persisted run reports and render the coverage matrix")
  .option("--results-dir <dir>", "directory containing run result JSON files (default: ./results)")
  .option("--run-id <id>", "restrict to a single run")
  .option("--format <fmt>", "markdown | json (default: markdown)")
  .option("--output <path>", "write to file (default: stdout)")
  .option("--matrix", "render the rule × probe coverage matrix")
  .option("--include-probes <path>", "aggregate harness probe results for gap analysis")
  .action((opts: Record<string, unknown>) => {
    const format = opts["format"] as string | undefined;
    if (format && format !== "markdown" && format !== "json") {
      console.error(`error: invalid --format "${format}". Use markdown or json.`);
      process.exit(2);
    }
    const options: ReportOptions = {
      resultsDir: opts["resultsDir"] as string | undefined,
      runId: opts["runId"] as string | undefined,
      format: format as "markdown" | "json" | undefined,
      output: opts["output"] as string | undefined,
      matrix: Boolean(opts["matrix"]),
      includeProbes: opts["includeProbes"] as string | undefined,
    };
    const { output, exitCode } = runReport(options);
    process.stdout.write(output + "\n");
    process.exit(exitCode);
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err);
  process.exit(2);
});
