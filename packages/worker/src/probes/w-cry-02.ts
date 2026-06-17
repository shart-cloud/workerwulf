import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wCry02: Probe = async ({ runId }) => {
  const tricky = crypto.subtle as unknown as {
    generateKey(a: unknown, e: boolean, u: string[]): Promise<{ privateKey: unknown; publicKey: unknown }>;
    exportKey(f: string, k: unknown): Promise<ArrayBuffer | Record<string, unknown>>;
  };
  const details: Record<string, unknown> = {};

  // Extractable key
  const ext: Record<string, unknown> = {};
  try {
    const kp = await tricky.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    ext.generated = true;

    try {
      const pkcs8 = await tricky.exportKey("pkcs8", kp.privateKey);
      ext.pkcs8_export = (pkcs8 as ArrayBuffer).byteLength > 0;
    } catch (err) {
      ext.pkcs8_export = false;
      ext.pkcs8_error = err instanceof Error ? err.message : String(err);
    }

    try {
      const jwk = await tricky.exportKey("jwk", kp.privateKey);
      const j = jwk as Record<string, unknown>;
      ext.jwk_export = typeof j.d === "string";
    } catch (err) {
      ext.jwk_export = false;
      ext.jwk_error = err instanceof Error ? err.message : String(err);
    }

    try {
      const raw = await tricky.exportKey("raw", kp.publicKey);
      ext.raw_public_export = (raw as ArrayBuffer).byteLength > 0;
    } catch (err) {
      ext.raw_public_export = false;
      ext.raw_public_error = err instanceof Error ? err.message : String(err);
    }

    try {
      const spki = await tricky.exportKey("spki", kp.publicKey);
      ext.spki_public_export = (spki as ArrayBuffer).byteLength > 0;
    } catch (err) {
      ext.spki_public_export = false;
      ext.spki_public_error = err instanceof Error ? err.message : String(err);
    }
  } catch (err) {
    ext.generated = false;
    ext.error = err instanceof Error ? err.message : String(err);
  }

  // Non-extractable key
  const next: Record<string, unknown> = {};
  try {
    const kp = await tricky.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    next.generated = true;

    try {
      await tricky.exportKey("pkcs8", kp.privateKey);
      next.pkcs8_export = true;
    } catch (err) {
      next.pkcs8_export = false;
      next.pkcs8_error = err instanceof Error ? err.message : String(err);
    }

    try {
      await tricky.exportKey("jwk", kp.privateKey);
      next.jwk_export = true;
    } catch (err) {
      next.jwk_export = false;
      next.jwk_error = err instanceof Error ? err.message : String(err);
    }
  } catch (err) {
    next.generated = false;
    next.error = err instanceof Error ? err.message : String(err);
  }

  // Bypass attempts
  const bypass: Record<string, boolean | string> = {};
  try {
    const kp = await tricky.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    try {
      const cloned = structuredClone(kp);
      bypass.structured_clone = cloned !== undefined;
    } catch (err) {
      bypass.structured_clone = err instanceof Error ? err.message.slice(0, 60) : "error";
    }

    try {
      const json = JSON.stringify(kp);
      bypass.JSON_stringify = json !== undefined && json !== "{}";
    } catch (err) {
      bypass.JSON_stringify = err instanceof Error ? err.message.slice(0, 60) : "error";
    }

    try {
      const props = Object.getOwnPropertyNames(kp as object);
      bypass.own_properties = props.length > 0 ? props.join(",") : "(empty)";
    } catch (err) {
      bypass.own_properties = err instanceof Error ? err.message.slice(0, 60) : "error";
    }
  } catch (err) {
    bypass.key_gen_failed = err instanceof Error ? err.message : String(err);
  }

  const extractableBlocked = ext.pkcs8_export === true && next.pkcs8_export === false;

  return base({
    test_id: "W-CRY-02",
    track: "worker",
    description: "Test key export with extractable:true vs extractable:false, attempt bypasses",
    result: extractableBlocked ? "blocked" : "informational",
    severity: "informational",
    run_id: runId,
    details: {
      extractable_true: ext,
      extractable_false: next,
      bypass_attempts: bypass,
      bypass_succeeded: Object.values(bypass).some((v) => v === true),
    },
  });
};