import type { Probe } from "./index.js";
import { base, doFetch } from "./_helpers.js";

/**
 * DO-IDOR-01 — Durable Object IDOR via guessable idFromName() names.
 *
 * A Durable Object's identity is derived from the name passed to
 * `idFromName(name)`. If an application names per-user/per-tenant objects with a
 * guessable, sequential scheme (`account-1000`, `account-1001`, …), then the
 * name itself is the only thing gating access — an attacker who knows the scheme
 * can enumerate names and read other principals' private objects. This is the
 * Durable Object form of a classic Insecure Direct Object Reference.
 */
export const doIdor01: Probe = async ({ env, runId }) => {
  const ns = env.PREY_DO;
  const tag = (runId.slice(0, 8).replace(/[^a-zA-Z0-9]/g, "") || "run");

  // "Victim" app: each account's private data lives in a DO addressed by a
  // guessable sequential name. Seed a few accounts with recognizable canaries.
  const victimAccounts = [1000, 1001, 1002];
  for (const acct of victimAccounts) {
    const stub = ns.get(ns.idFromName(`account-${acct}`));
    const canary = `flag{do-idor-01-${acct}-${tag}}`;
    await doFetch(
      stub,
      `http://do/idor-put?key=ssn&val=${encodeURIComponent(canary)}`,
    );
  }

  // "Attacker" holds no reference to any victim object — only the naming
  // scheme. Enumerate a range and read whatever each name resolves to.
  const guessRange = [999, 1000, 1001, 1002, 1003];
  const recovered: Array<{ name: string; val: string }> = [];
  for (const acct of guessRange) {
    const name = `account-${acct}`;
    const stub = ns.get(ns.idFromName(name));
    const data = await doFetch<{ found?: boolean; val?: string | null }>(
      stub,
      "http://do/idor-get?key=ssn",
    );
    if (data.found && typeof data.val === "string" && data.val.includes("do-idor-01")) {
      recovered.push({ name, val: data.val });
    }
  }

  const leaked = recovered.length > 0;

  return base({
    test_id: "DO-IDOR-01",
    track: "durable",
    description:
      "Durable Object IDOR: guessable idFromName() names let an attacker enumerate and read other accounts' private objects",
    result: leaked ? "accessible" : "blocked",
    severity: leaked ? "high" : "informational",
    run_id: runId,
    tags: ["misconfig", "misconfig:idor"],
    details: {
      naming_scheme: "account-<sequential-id>",
      victim_accounts: victimAccounts.map((a) => `account-${a}`),
      guessed_range: guessRange.map((a) => `account-${a}`),
      recovered_count: recovered.length,
      recovered,
      note: "DO identity is derived from the name via idFromName(); a guessable name IS the capability. Because the mapping is deterministic across any binding to the namespace, any worker (incl. another script) that addresses the same name reaches the same object. Mitigations: newUniqueId() (DO-IDOR-02) or high-entropy names (DO-IDOR-03).",
    },
    comparison: {
      aws_lambda:
        "N/A (no Durable Object equivalent; analogous to IDOR on any object store keyed by a guessable id)",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
