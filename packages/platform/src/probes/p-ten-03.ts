import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

export const pTen03: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const victimInit = await invokeTenant<Record<string, unknown>>(c, "tenant-victim", "init", {}, { mode });
  const access = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "binding-access", {}, { mode });
  const ownKvRead = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "prey-kv-read", { key: "secret-doc" }, { mode });
  const victimBindingsPresent = (access.body.victim_bindings_present as string[] | undefined) ?? [];
  const victimReads = access.body.victim_reads as Record<string, unknown> | undefined;
  const directVictimCanaryRead = JSON.stringify(victimReads ?? {}).includes("flag{p-ten-03");
  const ownBindingCanaryRead = JSON.stringify(ownKvRead.body ?? {}).includes("flag{p-ten-03");
  const canaryRead = directVictimCanaryRead || ownBindingCanaryRead;

  return base({
    test_id: "P-TEN-03",
    track: "platform",
    description: "Cross-tenant binding access from attacker user Worker to victim tenant resources",
    result: canaryRead ? "accessible" : "blocked",
    severity: canaryRead ? "critical" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      victim_init: victimInit.body,
      prey_env_keys: access.body.prey_env_keys ?? [],
      victim_binding_guess_attempts: access.body.victim_binding_guess_attempts ?? [],
      victim_bindings_present: victimBindingsPresent,
      victim_canary_read: canaryRead,
      direct_victim_binding_canary_read: directVictimCanaryRead,
      own_binding_canary_read: ownBindingCanaryRead,
      own_binding_negative_check: ownKvRead.body,
      canaries_targeted: ["flag{p-ten-03-kv-canary}", "flag{p-ten-03-d1-canary}", "flag{p-ten-03-secret-canary}"],
      raw: access.body,
    },
  });
};
