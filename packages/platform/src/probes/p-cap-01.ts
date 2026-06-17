import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

export const pCap01: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "env-enum", {}, { mode });
  const operatorKeys = ((resp.body.operator_keys as string[] | undefined) ?? []).filter((key) => key !== "PREY_MARKER");
  const secretLikeStrings = (resp.body.secret_like_strings as string[] | undefined) ?? [];
  const leaked = operatorKeys.length > 0 || secretLikeStrings.length > 0;

  return base({
    test_id: "P-CAP-01",
    track: "platform",
    description: "Operator binding/secret bleed into a WfP user Worker env",
    result: leaked ? "accessible" : "blocked",
    severity: leaked ? "critical" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      env_keys: resp.body.env_keys ?? [],
      operator_bindings_leaked: operatorKeys,
      secrets_leaked: secretLikeStrings,
      raw: resp.body,
    },
  });
};
