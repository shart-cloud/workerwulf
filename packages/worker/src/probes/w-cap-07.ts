import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-CAP-07 — mTLS client-certificate capability-binding blast radius (misconfig).
 *
 * An `mtls_certificates` binding attaches a client certificate to outbound
 * requests made through the bound fetcher (`env.MTLS_FETCHER.fetch()`). A
 * compromised Worker thereby *borrows the certificate's identity* to authenticate
 * to an mTLS-protected origin — authenticated SSRF, strictly stronger than the
 * bare `fetch()` of W-NET-*: the request arrives at the backend already trusted,
 * so the cert becomes a skeleton key to whatever it was provisioned for. This
 * probe drives the bound fetcher at a target (?target=, default example.com) and
 * reports the response, demonstrating the Worker can wield the cert at will.
 *
 * Deploy-only: requires the live MTLS_FETCHER binding. Locally → blocked.
 */
export const wCap07: Probe = async ({ env, req, runId }) => {
  const mtls = env.MTLS_FETCHER;
  if (!mtls) {
    return base({
      test_id: "W-CAP-07",
      track: "worker",
      description:
        "mTLS certificate capability binding — borrow the client cert to authenticate to an mTLS-protected origin (authenticated SSRF)",
      target: "env.MTLS_FETCHER",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: { error: "MTLS_FETCHER binding not present (expected locally / pre-deploy)" },
    });
  }

  const url = new URL(req.url);
  const target = url.searchParams.get("target") ?? "https://example.com/";

  let status: number | null = null;
  let statusText: string | null = null;
  let respHeaders: Record<string, string> | null = null;
  let bodyPreview: string | null = null;
  let error: string | null = null;
  let fetched = false;

  try {
    const resp = await mtls.fetch(target, { method: "GET" });
    status = resp.status;
    statusText = resp.statusText;
    respHeaders = Object.fromEntries(resp.headers);
    bodyPreview = (await resp.text()).slice(0, 1024);
    fetched = true;
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return base({
    test_id: "W-CAP-07",
    track: "worker",
    description:
      "mTLS certificate capability binding — borrow the client cert to authenticate to an mTLS-protected origin (authenticated SSRF)",
    target: "env.MTLS_FETCHER",
    result: fetched ? "accessible" : error ? "error" : "partial",
    severity: fetched ? "high" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:binding"],
    details: {
      requested_target: target,
      http_status: status,
      http_status_text: statusText,
      response_headers: respHeaders,
      body_preview: bodyPreview,
      error,
      note: "An mTLS binding presents a client certificate the Worker never has to possess in cleartext — yet any code in the isolate can drive requests under that identity. Point ?target= at the mTLS-protected backend the cert was issued for to demonstrate authenticated reach.",
    },
    comparison: {
      aws_lambda:
        "accessible — analog to a private key / IAM Roles Anywhere cert in the function env used to reach a mutually-authenticated backend",
      azure_functions: "accessible — client cert from Key Vault used for backend mTLS",
      gcp_functions: "accessible — mTLS client cert / workload identity reaching a protected service",
    },
  });
};
