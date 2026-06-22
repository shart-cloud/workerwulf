import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode } from "./_helpers.js";

/**
 * P-TEN-04 — Cross-tenant Durable Object reach.
 *
 * Composes the DO-DYN-03 cross-object finding with the multi-tenant boundary: can
 * `tenant-prey` reach a *sibling* tenant's Durable Object by name/ID? Prey enumerates
 * its env for any DurableObjectNamespace-shaped binding, tries `idFromName` for the
 * victim's DO, and attempts to read `flag{p-ten-04-do-canary}`. Without a binding to
 * the victim's DO class in prey's scope, the namespace is unaddressable.
 *
 * Account-crossing-sensitive: only ever exercises the boundary between the two
 * self-owned tenants. A positive result implying reach across account/namespace
 * ownership halts testing and goes to Cloudflare via responsible disclosure first.
 */
export const pTen04: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "do-reach", {}, { mode });
  const b = resp.body ?? {};
  const canaryRead = Boolean(b.do_canary_read);
  const reachable = ((b.do_namespace_bindings as string[] | undefined)?.length ?? 0) > 0;

  return base({
    test_id: "P-TEN-04",
    track: "platform",
    description: "Cross-tenant Durable Object reach from attacker user Worker to a sibling tenant's DO",
    result: canaryRead ? "accessible" : "blocked",
    severity: canaryRead ? "critical" : "informational",
    run_id: c.runId,
    details: {
      namespace: mode,
      victim_do_binding_reachable: reachable,
      id_construction_possible: Boolean(b.id_construction_possible),
      do_canary_read: canaryRead,
      do_namespace_bindings: b.do_namespace_bindings ?? [],
      canary_targeted: "flag{p-ten-04-do-canary}",
      attempts: b.attempts ?? [],
      note: "Without a binding to the victim's DO class in prey's env, the namespace is unaddressable from prey.",
    },
  });
};
