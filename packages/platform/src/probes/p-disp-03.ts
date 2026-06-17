import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

export const pDisp03: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const current = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "metadata", {}, { mode });
  let trusted: Record<string, unknown> | null = null;
  let trustedError: string | null = null;

  if (mode === "untrusted" && c.env.DISPATCHER_TRUSTED) {
    try {
      trusted = (await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "metadata", {}, { mode: "trusted" })).body;
    } catch (err) {
      trustedError = err instanceof Error ? err.message : String(err);
    }
  }

  const cfPresent = Boolean(current.body.request_cf_present);
  const strings = JSON.stringify(current.body.env_string_values ?? {});
  const accountDiscoverable = /[a-f0-9]{32}|account/i.test(strings);
  const namespaceDiscoverable = /wulf-tenants|dispatch/i.test(strings);

  return base({
    test_id: "P-DISP-03",
    track: "platform",
    description: "Namespace/account metadata disclosure and request.cf untrusted-mode differential",
    result: cfPresent || accountDiscoverable || namespaceDiscoverable ? "partial" : "blocked",
    severity: cfPresent || accountDiscoverable || namespaceDiscoverable ? "low" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      untrusted: mode === "untrusted" ? current.body : null,
      current: current.body,
      trusted,
      trusted_error: trustedError,
      account_id_discoverable: accountDiscoverable,
      namespace_name_discoverable: namespaceDiscoverable,
    },
    comparison: {
      aws_lambda: "context object exposes account id, function ARN, and region",
      azure_functions: "HTTP trigger exposes request context and app settings when bound",
      gcp_functions: "function context has project/region metadata via environment/config",
    },
  });
};
