import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode, callbackTarget, checkCallback } from "./_helpers.js";

// The inert credential wulf-outbound injects (see wrangler.outbound.toml
// WULF_OUTBOUND_AUTH_TOKEN). Recovering it proves the user Worker can read it back.
const INJECTED_TOKEN = "wulf-outbound-injected-canary";

/**
 * P-CAP-03 — Outbound-Worker injected-credential exposure.
 *
 * Outbound Workers commonly inject auth (mint a JWT, add an API key) on allowlisted
 * requests, assuming the user Worker can't see the credential. This tests that
 * assumption against a **logging** upstream: prey fetches the (allowlisted) callbackd
 * endpoint; wulf-outbound injects `Authorization: Bearer <token>` on the way out;
 * callbackd records the request headers and exposes them via its unauthenticated
 * `/check`. The user Worker thus recovers the operator-injected credential.
 *
 * (Worker→*.workers.dev subrequests are rejected by the edge — CF error 1042 — so a
 * workers.dev reflector can't be used; the external callbackd droplet works.)
 * Documents the safe pattern: inject only to non-logging/non-reflecting upstreams and
 * scope credentials per-tenant.
 */
export const pCap03: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const since = new Date(Date.now() - 5000).toISOString();
  const target = callbackTarget(c, "P-CAP-03");

  // Prey fetches the logging upstream through the outbound Worker (which injects auth).
  const fetchResp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "echo-fetch", { target }, { mode });

  // Recover what the upstream captured — the path a user Worker would also take.
  const check = await checkCallback(c, "P-CAP-03", since);
  const checkStr = JSON.stringify(check);
  const directStr = JSON.stringify(fetchResp.body ?? {});

  const credentialInUpstreamLog = checkStr.includes(INJECTED_TOKEN);
  const credentialInDirectResponse = directStr.includes(INJECTED_TOKEN);
  const authHeaderLogged = /authorization/i.test(checkStr);
  const credentialVisible = credentialInUpstreamLog || credentialInDirectResponse;
  const reachedUpstream = (check as { found?: boolean }).found === true;

  const result = credentialVisible ? "accessible" : reachedUpstream ? "blocked" : "partial";

  return base({
    test_id: "P-CAP-03",
    track: "platform",
    description: "Outbound-Worker injected-credential exposure via a logging/reflecting allowlisted upstream",
    result,
    severity: credentialVisible ? "high" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      upstream: target,
      outbound_injects_header: "Authorization",
      reached_upstream: reachedUpstream,
      injected_credential_logged_by_upstream: credentialInUpstreamLog,
      injected_credential_in_direct_response: credentialInDirectResponse,
      authorization_header_present_in_upstream_log: authHeaderLogged,
      credential_visible_to_user_worker: credentialVisible,
      direct_response: fetchResp.body,
      upstream_check: check,
      note: "wulf-outbound injects Authorization on allowlisted fetches; callbackd logs request headers and exposes them via the unauthenticated /check, so the user Worker recovers the operator-injected credential. Operators should inject only to non-logging/non-reflecting upstreams and scope credentials per-tenant.",
    },
  });
};
