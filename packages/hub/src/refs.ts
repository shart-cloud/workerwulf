/**
 * Deterministic, account-qualified resource refs (POSTURE_PLAN.md §6).
 * `cf:<account_id>/<kind>/<id…>`, with each id segment URL-encoded.
 */
const seg = encodeURIComponent;

export const scriptRef = (account: string, script: string) => `cf:${account}/workers/${seg(script)}`;
export const bindingRef = (account: string, script: string, binding: string) =>
  `${scriptRef(account, script)}/bindings/${seg(binding)}`;
export const namespaceRef = (account: string, namespace: string) => `cf:${account}/dispatch/${seg(namespace)}`;
export const accountRef = (account: string) => `cf:${account}/account`;

/**
 * The ref for a finding's human-readable resource: `script:x`,
 * `script:x:binding:Y` or `namespace:n`. Anything else is account-level.
 */
export function resourceRef(account: string, resource: string): string {
  const binding = resource.match(/^script:([^:]+):binding:(.+)$/);
  if (binding) return bindingRef(account, binding[1]!, binding[2]!);
  const script = resource.match(/^script:([^:]+)/);
  if (script) return scriptRef(account, script[1]!);
  const ns = resource.match(/^namespace:([^:]+)/);
  if (ns) return namespaceRef(account, ns[1]!);
  return accountRef(account);
}

/** The coverage target whose reads a finding depends on: `script:x`, `namespace:n` or `account`. */
export function coverageTarget(resource: string): string {
  const m = resource.match(/^(script:[^:]+|namespace:[^:]+)/);
  return m ? m[1]! : "account";
}
