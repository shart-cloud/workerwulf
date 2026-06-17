import type { Probe } from "./index.js";
import { base, doFetch } from "./_helpers.js";

/**
 * DO-IDOR-02 — Control: newUniqueId() defeats name-guessing.
 *
 * The secure counterpart to DO-IDOR-01. When the victim object is created with
 * `newUniqueId()` (an opaque, high-entropy id) instead of `idFromName(name)`,
 * an attacker who only guesses *names* can never address it — reaching it
 * requires the exact id string via `idFromString()`. A `blocked` verdict here is
 * the SECURE outcome, and it demonstrates that the DO-IDOR-01 breach is an
 * operator misconfiguration (guessable name), not an inherent DO flaw.
 */
export const doIdor02: Probe = async ({ env, runId }) => {
  const ns = env.PREY_DO;
  const tag = (runId.slice(0, 8).replace(/[^a-zA-Z0-9]/g, "") || "run");
  const secret = `flag{do-idor-02-${tag}}`;

  // "Victim" stores the secret in an object addressed by an OPAQUE unique id.
  const uniqueId = ns.newUniqueId();
  const victimStub = ns.get(uniqueId);
  await doFetch(
    victimStub,
    `http://do/idor-put?key=ssn&val=${encodeURIComponent(secret)}`,
  );

  // Sanity: the legitimate holder of the opaque id can read it back.
  const legit = await doFetch<{ val?: string | null }>(
    victimStub,
    "http://do/idor-get?key=ssn",
  );

  // "Attacker" enumerates plausible names — including the unique id rendered as
  // a *name* (idFromName hashes it, so it does NOT collide with the real object).
  const guesses = [
    "account-1000",
    "account-1001",
    "user-1",
    "ssn",
    "ai-test",
    "DO-IDOR-02",
    uniqueId.toString(),
  ];
  const recovered: string[] = [];
  for (const name of guesses) {
    const stub = ns.get(ns.idFromName(name));
    const data = await doFetch<{ found?: boolean; val?: string | null }>(
      stub,
      "http://do/idor-get?key=ssn",
    );
    if (data.found && data.val === secret) recovered.push(name);
  }

  const reachableByGuess = recovered.length > 0;

  return base({
    test_id: "DO-IDOR-02",
    track: "durable",
    description:
      "Control: a newUniqueId() Durable Object is not reachable by guessing names (the secure baseline for DO-IDOR-01)",
    result: reachableByGuess ? "accessible" : "blocked",
    severity: reachableByGuess ? "high" : "informational",
    run_id: runId,
    tags: ["misconfig", "misconfig:idor"],
    details: {
      control: "newUniqueId()",
      legit_read_ok: legit?.val === secret,
      guessed_names: guesses,
      recovered_by_guess: recovered,
      note: "Blocked is the SECURE outcome. Opaque unique ids cannot be reached via idFromName(); addressing them requires the exact id string (idFromString). This isolates DO-IDOR-01 as a misconfiguration, not a platform flaw.",
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
