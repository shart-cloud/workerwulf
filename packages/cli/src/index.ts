#!/usr/bin/env -S npx tsx
import { Command } from "commander";

import { runAudit, type AuditOptions } from "./commands/audit.js";
import { runScan, type ScanOptions } from "./commands/scan.js";
import type { Severity } from "./engine/rule.js";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

const program = new Command();

program
  .name("wulf")
  .description(
    "Cloudflare Workers security scanner — encodes workerwulf research findings " +
      "as static detection rules over wrangler config and Worker source.",
  )
  .version("0.0.0");

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
    };
    const { output, exitCode } = await runScan(options);
    process.stdout.write(output + "\n");
    process.exit(exitCode);
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err);
  process.exit(2);
});
