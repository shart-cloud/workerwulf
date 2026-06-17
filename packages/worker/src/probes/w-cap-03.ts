import { EmailMessage } from "cloudflare:email";
import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-CAP-03 — send_email capability-binding blast radius (exfil / phishing channel).
 *
 * A Worker bound to `send_email` can send mail from a verified domain — any code
 * that runs in the Worker becomes an outbound email channel for data exfil or
 * phishing. Cloudflare restricts delivery to the binding's configured
 * destination_address, which we use as the safeguard here.
 *
 * Responsible posture (HackerOne/SANS): delivery is pinned to a single
 * researcher-owned verified address via the binding's `destination_address`; the
 * payload is a benign canary; no third-party address is ever targeted or spoofed.
 *
 * Deploy-only: requires the live SEND_EMAIL binding + verified Email Routing.
 */
export const wCap03: Probe = async ({ env, runId }) => {
  const send = env.SEND_EMAIL;
  if (!send) {
    return base({
      test_id: "W-CAP-03",
      track: "worker",
      description:
        "send_email capability binding — a compromised Worker becomes an email exfil/phishing channel",
      target: "env.SEND_EMAIL",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: { error: "SEND_EMAIL binding not present (expected locally / pre-deploy)" },
    });
  }

  const from = env.WULF_EMAIL_FROM;
  const to = env.WULF_EMAIL_TO;
  if (!from || !to) {
    return base({
      test_id: "W-CAP-03",
      track: "worker",
      description:
        "send_email capability binding — a compromised Worker becomes an email exfil/phishing channel",
      target: "env.SEND_EMAIL",
      result: "partial",
      severity: "medium",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: {
        binding_present: true,
        error:
          "WULF_EMAIL_FROM / WULF_EMAIL_TO not configured — set [vars] to a verified from-domain and the pinned destination address",
      },
    });
  }

  const fromDomain = from.split("@")[1] ?? "wulf.invalid";
  const canary = "flag{w-cap-03-send-email-canary}";
  const raw = [
    `From: ${from}`,
    `To: ${to}`,
    "Subject: Workerwulf W-CAP-03 capability canary",
    `Message-ID: <wulf-cap-03-${runId}@${fromDomain}>`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    `${canary} run_id=${runId}`,
    "Benign canary from Workerwulf W-CAP-03 demonstrating the send_email binding capability. Destination is pinned to a researcher-owned verified address.",
  ].join("\r\n");

  let sent = false;
  let error: string | null = null;
  try {
    await send.send(new EmailMessage(from, to, raw));
    sent = true;
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return base({
    test_id: "W-CAP-03",
    track: "worker",
    description:
      "send_email capability binding — a compromised Worker becomes an email exfil/phishing channel",
    target: "env.SEND_EMAIL",
    result: sent ? "accessible" : error ? "error" : "partial",
    severity: sent ? "high" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:binding"],
    details: {
      from,
      to,
      canary,
      sent,
      error,
      safeguard:
        "Delivery pinned to the binding's verified destination_address; benign canary payload only; no third-party targeting or spoofing.",
      note: "A send_email binding lets any code in the Worker send mail from a verified domain — an exfil and phishing primitive. The platform caps delivery to the configured destination(s); within that, an attacker can exfil data or phish.",
    },
    comparison: {
      aws_lambda: "accessible — SES SendEmail under the function's IAM role",
      azure_functions: "n/a — requires a mail provider + credentials",
      gcp_functions: "n/a — requires a mail provider + credentials",
    },
  });
};
