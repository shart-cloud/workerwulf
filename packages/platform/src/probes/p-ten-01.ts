import type { Probe } from "./index.js";
import { base, invokeTenant } from "./_helpers.js";

export const pTen01: Probe = async (c) => {
  const key = `https://wulf-platform.invalid/cache/${c.runId}`;
  const value = `flag{p-ten-01-cache-${c.runId.slice(0, 8)}}`;
  const untrusted = await runCachePair(c, "untrusted", key, value);
  let trusted: Record<string, unknown> | null = null;
  let trustedError: string | null = null;
  if (c.env.DISPATCHER_TRUSTED) {
    try {
      trusted = await runCachePair(c, "trusted", `${key}/trusted`, `${value}-trusted`);
    } catch (err) {
      trustedError = err instanceof Error ? err.message : String(err);
    }
  }

  const untrustedRead = Boolean(untrusted.prey_read?.hit);

  return base({
    test_id: "P-TEN-01",
    track: "platform",
    description: "Cross-tenant Cache API visibility, untrusted-mode differential",
    result: untrustedRead ? "accessible" : "blocked",
    severity: untrustedRead ? "critical" : "informational",
    run_id: c.runId,
    details: {
      untrusted: { cross_tenant_default_cache_read: untrustedRead, ...untrusted },
      trusted,
      trusted_error: trustedError,
    },
  });
};

async function runCachePair(c: Parameters<Probe>[0], mode: "untrusted" | "trusted", key: string, value: string) {
  const victimWrite = await invokeTenant<Record<string, unknown>>(c, "tenant-victim", "cache-write", { key, value }, { mode });
  const preyRead = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "cache-read", { key }, { mode });
  return { victim_write: victimWrite.body, prey_read: preyRead.body };
}
