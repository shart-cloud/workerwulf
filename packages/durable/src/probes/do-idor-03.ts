import type { Probe } from "./index.js";
import { base, doFetch } from "./_helpers.js";

/**
 * DO-IDOR-03 — Nuance: idFromName() is deterministic, so safety is entirely a
 * function of name entropy.
 *
 * idFromName(name) maps a name to the same Durable Object id every time and from
 * any binding to the namespace — so an attacker can precompute the id space for
 * a guessable scheme *offline*. The corollary is the actual fix: idFromName() is
 * perfectly safe IF the name is high-entropy. This probe confirms determinism
 * and shows that a 128-bit-random name resists the same enumeration that breaks
 * DO-IDOR-01.
 */
export const doIdor03: Probe = async ({ env, runId }) => {
  const ns = env.PREY_DO;
  const tag = (runId.slice(0, 8).replace(/[^a-zA-Z0-9]/g, "") || "run");

  // (a) Determinism: the same name resolves to the same id across calls.
  const sampleName = "account-1000";
  const id1 = ns.idFromName(sampleName).toString();
  const id2 = ns.idFromName(sampleName).toString();
  const deterministic = id1 === id2;

  // (b) Mitigation: store the secret under a high-entropy name. idFromName() is
  // still used — only the name's guessability changed.
  const highEntropyName = `account-${crypto.randomUUID()}`;
  const secret = `flag{do-idor-03-${tag}}`;
  const victim = ns.get(ns.idFromName(highEntropyName));
  await doFetch(
    victim,
    `http://do/idor-put?key=ssn&val=${encodeURIComponent(secret)}`,
  );

  // Attacker enumerates the sequential scheme — never reaches the random name.
  const guesses = [1000, 1001, 1002, 1003, 1004].map((a) => `account-${a}`);
  let recovered = 0;
  for (const name of guesses) {
    const stub = ns.get(ns.idFromName(name));
    const data = await doFetch<{ found?: boolean; val?: string | null }>(
      stub,
      "http://do/idor-get?key=ssn",
    );
    if (data.found && data.val === secret) recovered++;
  }
  const guessableDespiteEntropy = recovered > 0;

  return base({
    test_id: "DO-IDOR-03",
    track: "durable",
    description:
      "Durable Object IDOR nuance: idFromName() is deterministic and offline-precomputable, so object security depends entirely on name entropy",
    result: "informational",
    severity: guessableDespiteEntropy ? "high" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:idor"],
    details: {
      deterministic,
      id_first: id1,
      id_second: id2,
      high_entropy_name_used: highEntropyName.replace(/[0-9a-f-]{36}$/, "<uuid>"),
      enumeration_recovered_high_entropy: recovered,
      high_entropy_resists_enumeration: !guessableDespiteEntropy,
      note: "Determinism means ids are offline-precomputable and identical across any binding/script. The fix is not to abandon idFromName() but to give it an unguessable name (UUID/random token) — high-entropy names resist the DO-IDOR-01 enumeration entirely.",
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
