import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-CAP-06 — Queues producer capability-binding blast radius (misconfig).
 *
 * A Queues *producer* binding lets a compromised Worker inject arbitrary messages
 * into the async pipeline via `env.PREY_QUEUE.send()`. Whatever the consumer does
 * with a message — write storage, call a downstream service, fan out, run code —
 * the attacker now drives by forging messages, bypassing the producer's normal
 * call-site validation entirely. One binding buys lateral movement and pipeline
 * poisoning. This probe sends a single benign, run-tagged canary message (no
 * flood) and reports whether the queue accepted it.
 *
 * Deploy-only: requires the live PREY_QUEUE binding + a queue. Locally → blocked.
 */
export const wCap06: Probe = async ({ env, runId }) => {
  const queue = env.PREY_QUEUE;
  if (!queue) {
    return base({
      test_id: "W-CAP-06",
      track: "worker",
      description:
        "Queues producer capability binding — inject forged messages into the async pipeline via env.PREY_QUEUE.send()",
      target: "env.PREY_QUEUE",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: { error: "PREY_QUEUE binding not present (expected locally / pre-deploy)" },
    });
  }

  let sent = false;
  let error: string | null = null;
  const message = {
    wulf: "w-cap-06",
    run_id: runId,
    note: "flag{w-cap-06-queue-canary}",
    injected: "forged producer message — no call-site validation applied",
  };

  try {
    // Single message only — the capability is proven by acceptance, not volume.
    await queue.send(message);
    sent = true;
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return base({
    test_id: "W-CAP-06",
    track: "worker",
    description:
      "Queues producer capability binding — inject forged messages into the async pipeline via env.PREY_QUEUE.send()",
    target: "env.PREY_QUEUE",
    result: sent ? "accessible" : error ? "error" : "partial",
    severity: sent ? "high" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:binding"],
    details: {
      message_sent: sent,
      message,
      error,
      note: "A producer binding is unauthenticated write access to the consumer's input. Forged messages reach whatever the consumer trusts — storage writes, downstream calls, fan-out — with none of the producer's normal validation. Lateral movement / pipeline poisoning from one binding.",
    },
    comparison: {
      aws_lambda:
        "accessible — equivalent to sqs:SendMessage / sns:Publish granted to the function role",
      azure_functions: "accessible — Service Bus / Storage Queue send rights in the function identity",
      gcp_functions: "accessible — pubsub.topics.publish on the runtime service account",
    },
  });
};
