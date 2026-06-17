import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wObj04: Probe = async ({ runId }) => {
  const nav = (globalThis as Record<string, unknown>).navigator as Record<string, unknown> | undefined;
  const expected = [
    "userAgent",
    "platform",
    "language",
    "languages",
    "hardwareConcurrency",
    "deviceMemory",
    "geolocation",
    "bluetooth",
    "serviceWorker",
    "cookieEnabled",
    "onLine",
  ];

  if (!nav) {
    return base({
      test_id: "W-OBJ-04",
      track: "worker",
      description: "Enumerate navigator object fingerprinting data",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      details: { navigator_available: false },
    });
  }

  const ownProperties = Object.getOwnPropertyNames(nav).sort();
  const protoProperties = Object.getOwnPropertyNames(Object.getPrototypeOf(nav) ?? {}).sort();
  const allProperties = Array.from(new Set([...ownProperties, ...protoProperties])).sort();
  const values: Record<string, unknown> = {};

  for (const key of expected) {
    try {
      const value = nav[key];
      values[key] = typeof value === "function" ? "function" : value ?? null;
    } catch (err) {
      values[key] = { error: err instanceof Error ? err.message : String(err) };
    }
  }

  return base({
    test_id: "W-OBJ-04",
    track: "worker",
    description: "Enumerate navigator object fingerprinting data",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      navigator_available: true,
      values,
      own_properties: ownProperties,
      prototype_properties: protoProperties,
      properties_present: expected.filter((key) => key in nav),
      properties_missing: expected.filter((key) => !(key in nav)),
      total: allProperties.length,
    },
  });
};
