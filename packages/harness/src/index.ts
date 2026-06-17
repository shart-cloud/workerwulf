#!/usr/bin/env -S npx tsx
import { cmdRun } from "./cmd-run.js";
import { cmdAnalyze } from "./cmd-analyze.js";

const HELP = `wulf — Cloudflare Prey test harness

commands:
  run        execute probes against a deployed/running worker
  analyze    aggregate results into a markdown findings report

usage:
  wulf run --all
  wulf run --test W-NET-02
  wulf run --track worker
  wulf run --track ai --model @cf/meta/llama-3.1-8b-instruct --prompt-tier hardened
  wulf run --track platform --namespace untrusted
  wulf analyze --results-dir results [--output report.md]

run flags:
  --all                       run every probe the worker exposes
  --track <worker|dynamic|durable|ai|platform>
  --test <test_id>
  --base-url <url>            override target (default http://127.0.0.1:8787)
  --output <dir>              results dir (default ./results)
  --run-id <id>               pin a run id (default: random uuid)
  --model <model>             AI model override (default: @cf/meta/llama-3.1-8b-instruct)
  --prompt-tier <tier>        AI prompt tier: naive|basic|hardened|defense
  --global-outbound <mode>    AI sandbox globalOutbound: open|null
  --namespace <mode>          Platform namespace mode: untrusted|trusted|both

analyze flags:
  --results-dir <dir>         results root (default ./results)
  --output <file>             output markdown path (default: stdout)
  --run-id <id>               restrict to a single run
`;

async function main(): Promise<void> {
  const [, , cmd, ...rest] = process.argv;

  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    process.stdout.write(HELP);
    process.exit(cmd ? 0 : 1);
  }

  if (cmd === "run") return cmdRun(rest);
  if (cmd === "analyze") return cmdAnalyze(rest);

  process.stderr.write(`unknown command: ${cmd}\n\n${HELP}`);
  process.exit(2);
}

await main();
