import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

// The inert credential wulf-outbound injects (see wrangler.outbound.toml
// WULF_OUTBOUND_AUTH_TOKEN). Reflecting it back proves the user Worker can read it.
const INJECTED_TOKEN = "wulf-outbound-injected-canary";

/**
 * P-CAP-03 — Outbound-Worker injected-credential exposure.
 *
 * Outbound Workers commonly inject auth (mint a JWT, add an API key) on allowlisted
 * requests, assuming the user Worker can't see the credential. This tests that
 * assumption: prey fetches an allowlisted **header-reflecting** upstream (`wulf-echo`
 * on *.workers.dev); wulf-outbound injects `Authorization: Bearer <token>` on the way
 * out; the echo reflects it; prey reads it back from the response body.
 *
 * Documents the safe pattern: inject only to non-reflecting upstreams / scope
 * credentials per-tenant.
 */
export const pCap03: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const echoUrl = c.env.WULF_ECHO_URL ?? "https://wulf-echo.sharted.workers.dev/";
  const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "echo-fetch", { target: echoUrl }, { mode });
  const body = (resp.body ?? {}) as { reachable?: boolean; status?: number; body?: string };
  const bodyStr = JSON.stringify(resp.body ?? {});

  const tokenVisible = bodyStr.includes(INJECTED_TOKEN);
  const authHeaderReflected = /"authorization"/i.test(bodyStr);
  // The reflecting upstream must actually be reachable through the outbound path for
  // the test to be conclusive. Worker→*.workers.dev subrequests are rejected by the
  // edge (CF error 1042), so a workers.dev echo can't be exercised in this deploy.
  const upstreamReachable = body.reachable === true && (body.status ?? 0) < 400 && !/error code: 1042/i.test(body.body ?? "");

  const result = tokenVisible ? "accessible" : upstreamReachable ? "blocked" : "partial";

  return base({
    test_id: "P-CAP-03",
    track: "platform",
    description: "Outbound-Worker injected-credential exposure via a reflecting allowlisted upstream",
    result,
    severity: tokenVisible ? "high" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      echo_target: echoUrl,
      outbound_injects_header: "Authorization",
      reflecting_upstream_reachable: upstreamReachable,
      authorization_header_reflected: authHeaderReflected,
      credential_visible_to_user_worker_via_echo: tokenVisible,
      echo_response: resp.body,
      note: upstreamReachable
        ? "If the allowlisted upstream reflects request headers, the user Worker reads back the operator-injected credential. Operators should inject only to non-reflecting upstreams / scope credentials per-tenant."
        : "INCONCLUSIVE: the reflecting echo upstream was unreachable through the outbound path (CF error 1042 blocks Worker→*.workers.dev subrequests). To demonstrate the positive case, host the reflector on a custom domain on the outbound allowlist. The injection mechanism (wulf-outbound adds Authorization) is confirmed by code.",
    },
  });
};
