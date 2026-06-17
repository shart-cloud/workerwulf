import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wCry01: Probe = async ({ runId }) => {
  const subtle = crypto.subtle;
  const results: Record<string, Record<string, boolean | string>> = {};
  const sub = subtle as unknown as {
    generateKey(a: unknown, e: boolean, u: string[]): Promise<unknown>;
    encrypt(a: unknown, k: unknown, d: BufferSource): Promise<ArrayBuffer>;
    decrypt(a: unknown, k: unknown, d: BufferSource): Promise<ArrayBuffer>;
    sign(a: unknown, k: unknown, d: BufferSource): Promise<ArrayBuffer>;
    verify(a: unknown, k: unknown, s: BufferSource, d: BufferSource): Promise<boolean>;
    deriveBits(a: unknown, k: unknown, l: number): Promise<ArrayBuffer>;
    deriveKey(a: unknown, k: unknown, d: unknown, e: boolean, u: string[]): Promise<unknown>;
    digest(a: string, d: BufferSource): Promise<ArrayBuffer>;
    importKey(f: string, m: BufferSource, a: string, e: boolean, u: string[]): Promise<unknown>;
    exportKey(f: string, k: unknown): Promise<unknown>;
  };

  const testCases: Array<{
    name: string;
    ops: string[];
    genParams: Record<string, unknown>;
    isKeyPair?: boolean;
  }> = [
    { name: "AES-GCM", ops: ["generateKey", "encrypt", "decrypt"], genParams: { name: "AES-GCM", length: 256 } },
    { name: "AES-CBC", ops: ["generateKey", "encrypt", "decrypt"], genParams: { name: "AES-CBC", length: 256 } },
    { name: "AES-CTR", ops: ["generateKey", "encrypt", "decrypt"], genParams: { name: "AES-CTR", length: 256 } },
    { name: "RSA-OAEP", ops: ["generateKey", "encrypt", "decrypt"], genParams: { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, isKeyPair: true },
    { name: "RSASSA-PKCS1-v1_5", ops: ["generateKey", "sign", "verify"], genParams: { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, isKeyPair: true },
    { name: "RSA-PSS", ops: ["generateKey", "sign", "verify"], genParams: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, isKeyPair: true },
    { name: "ECDSA", ops: ["generateKey", "sign", "verify"], genParams: { name: "ECDSA", namedCurve: "P-256" }, isKeyPair: true },
    { name: "ECDH", ops: ["generateKey", "deriveBits"], genParams: { name: "ECDH", namedCurve: "P-256" }, isKeyPair: true },
    { name: "Ed25519", ops: ["generateKey", "sign", "verify"], genParams: { name: "Ed25519" }, isKeyPair: true },
    { name: "X25519", ops: ["generateKey", "deriveBits"], genParams: { name: "X25519" }, isKeyPair: true },
    { name: "HMAC", ops: ["generateKey", "sign", "verify"], genParams: { name: "HMAC", hash: "SHA-256" } },
    { name: "PBKDF2", ops: ["deriveBits", "deriveKey"], genParams: { name: "PBKDF2", salt: new Uint8Array(16), iterations: 1000, hash: "SHA-256" } },
    { name: "HKDF", ops: ["deriveBits", "deriveKey"], genParams: { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new Uint8Array(0) } },
  ];

  for (const tc of testCases) {
    const algoResults: Record<string, boolean | string> = {};
    results[tc.name] = algoResults;

    let cachedKey: unknown = null;

    for (const op of tc.ops) {
      try {
        switch (op) {
          case "generateKey": {
            cachedKey = await sub.generateKey(
              tc.genParams,
              true,
              tc.isKeyPair ? ["sign", "verify"] : ["encrypt", "decrypt"],
            );
            algoResults.generateKey = true;
            break;
          }
          case "encrypt": {
            const key = await sub.generateKey(tc.genParams, true, ["encrypt"]);
            const data = new Uint8Array(16);
            await sub.encrypt({ name: tc.name, iv: new Uint8Array(12), tagLength: 128 }, key, data);
            algoResults.encrypt = true;
            break;
          }
          case "decrypt": {
            const key = await sub.generateKey(tc.genParams, true, ["encrypt", "decrypt"]);
            const data = new Uint8Array(16);
            const enc = await sub.encrypt({ name: tc.name, iv: new Uint8Array(12), tagLength: 128 }, key, data);
            await sub.decrypt({ name: tc.name, iv: new Uint8Array(12), tagLength: 128 }, key, enc);
            algoResults.decrypt = true;
            break;
          }
          case "sign": {
            if (tc.name === "HMAC") {
              const key = await sub.generateKey(tc.genParams, true, ["sign", "verify"]);
              const data = new Uint8Array(32);
              await sub.sign("HMAC", key, data);
            } else {
              const kp = await sub.generateKey(tc.genParams, true, ["sign", "verify"]) as { privateKey: unknown };
              const data = new Uint8Array(32);
              await sub.sign({ name: tc.name, hash: "SHA-256" }, kp.privateKey, data);
            }
            algoResults.sign = true;
            break;
          }
          case "verify": {
            if (tc.name === "HMAC") {
              const key = await sub.generateKey(tc.genParams, true, ["sign", "verify"]);
              const data = new Uint8Array(32);
              const sig = await sub.sign("HMAC", key, data);
              const ok = await sub.verify("HMAC", key, sig, data);
              algoResults.verify = ok;
            } else {
              const kp = await sub.generateKey(tc.genParams, true, ["sign", "verify"]) as { privateKey: unknown; publicKey: unknown };
              const data = new Uint8Array(32);
              const sig = await sub.sign({ name: tc.name, hash: "SHA-256" }, kp.privateKey, data);
              const ok = await sub.verify({ name: tc.name, hash: "SHA-256" }, kp.publicKey, sig, data);
              algoResults.verify = ok;
            }
            break;
          }
          case "deriveBits": {
            if (tc.name === "PBKDF2") {
              const baseKey = await sub.importKey("raw", new TextEncoder().encode("password"), "PBKDF2", false, ["deriveBits"]);
              await sub.deriveBits(tc.genParams, baseKey, 256);
            } else if (tc.name === "HKDF") {
              const baseKey = await sub.importKey("raw", new TextEncoder().encode("seed"), "HKDF", false, ["deriveBits"]);
              await sub.deriveBits(tc.genParams, baseKey, 256);
            } else if (tc.name === "ECDH" || tc.name === "X25519") {
              const kpA = await sub.generateKey(tc.genParams, true, ["deriveBits"]) as { privateKey: unknown; publicKey: unknown };
              const kpB = await sub.generateKey(tc.genParams, true, ["deriveBits"]) as { publicKey: unknown };
              await sub.deriveBits({ name: tc.name, public: kpB.publicKey }, kpA.privateKey, 256);
            }
            algoResults.deriveBits = true;
            break;
          }
          case "deriveKey": {
            const masterKey = await sub.importKey("raw", new TextEncoder().encode("master"), tc.name, false, ["deriveKey"]);
            const derived = await sub.deriveKey(tc.genParams, masterKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
            algoResults.deriveKey = derived !== undefined;
            break;
          }
        }
      } catch (err) {
        algoResults[op] = err instanceof Error ? err.message.slice(0, 80) : "error";
      }
    }
  }

  for (const hash of ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]) {
    try {
      const data = new Uint8Array(64);
      await sub.digest(hash, data);
      results[hash] = { digest: true };
    } catch (err) {
      results[hash] = { digest: err instanceof Error ? err.message.slice(0, 80) : "error" };
    }
  }

  let totalSupported = 0;
  let totalTested = 0;
  for (const [, algoResults] of Object.entries(results)) {
    for (const [, v] of Object.entries(algoResults)) {
      totalTested++;
      if (v === true) totalSupported++;
    }
  }

  return base({
    test_id: "W-CRY-01",
    track: "worker",
    description: "Enumerate Web Crypto algorithm support matrix",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      algorithms: results,
      total_supported: totalSupported,
      total_tested: totalTested,
    },
  });
};