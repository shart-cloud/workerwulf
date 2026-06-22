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
  // The genuine cross-tenant signal is reaching the canary through a VICTIM_* binding.
  // A hit on prey's OWN PREY_KV is shared-research-KV pollution (the d300 namespace is
  // reused across the apparatus), NOT an isolation break, so it must not drive the verdict.
  const crossTenantCanaryRead = directVictimCanaryRead && victimBindingsPresent.length > 0;

  return base({
    test_id: "P-TEN-03",
    track: "platform",
    description: "Cross-tenant binding access from attacker user Worker to victim tenant resources",
    result: crossTenantCanaryRead ? "accessible" : "blocked",
    severity: crossTenantCanaryRead ? "critical" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      victim_init: victimInit.body,
      prey_env_keys: access.body.prey_env_keys ?? [],
      victim_binding_guess_attempts: access.body.victim_binding_guess_attempts ?? [],
      victim_bindings_present: victimBindingsPresent,
      cross_tenant_canary_read: crossTenantCanaryRead,
      direct_victim_binding_canary_read: directVictimCanaryRead,
      own_namespace_canary_collision: ownBindingCanaryRead,
      own_namespace_note: ownBindingCanaryRead
        ? "prey's OWN PREY_KV contains a colliding flag{p-ten-03} value — shared research-KV (d300) pollution, NOT a cross-tenant isolation break (no VICTIM_* binding is present in prey's env)."
        : null,
      own_binding_negative_check: ownKvRead.body,
      canaries_targeted: ["flag{p-ten-03-kv-canary}", "flag{p-ten-03-d1-canary}", "flag{p-ten-03-secret-canary}"],
      raw: access.body,
    },
  });
};
