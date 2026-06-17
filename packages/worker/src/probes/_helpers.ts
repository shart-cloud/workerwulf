import type { ProbeResult } from "@wulf/shared";

export function now(): string {
  return new Date().toISOString();
}

export function base(
  partial: Omit<ProbeResult, "timestamp">,
): ProbeResult {
  return { timestamp: now(), ...partial };
}
