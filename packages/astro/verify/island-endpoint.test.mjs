// Local oracle for the A-ISLAND probes — drives the REAL compiled Astro
// server-island endpoint + encryption from a local checkout, with no wrangler
// or Astro build required. Proves what each probe asserts over HTTP.
//
//   ASTRO_PKG=/path/to/packages/astro node --test verify/island-endpoint.test.mjs
//
// Requires the astro package to be built (dist/ present): cd $ASTRO_PKG && pnpm build
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { existsSync } from "node:fs";
import { pathToFileURL } from "node:url";

const ASTRO_PKG = process.env.ASTRO_PKG ?? "/home/jg/git/astro/packages/astro";
const dist = (rel) => {
  const abs = path.join(ASTRO_PKG, "dist", rel);
  if (!existsSync(abs)) throw new Error(`Missing ${abs} — build astro first (cd ${ASTRO_PKG} && pnpm build)`);
  return pathToFileURL(abs).href;
};

const { getRequestData } = await import(dist("core/server-islands/endpoint.js"));
const { createKey, encryptString, decryptString } = await import(dist("core/encryption.js"));

const islandUrl = "http://victim.example/_server-islands/probe";
const postReq = (body, headers = { "content-type": "application/json" }) =>
  new Request(islandUrl, { method: "POST", headers, body });

// ---- A-ISLAND-01: null/scalar body parsing ----
test("A-ISLAND-01: POST body `null` throws an UNCAUGHT TypeError (→ 500, not 400)", async () => {
  await assert.rejects(() => getRequestData(postReq("null")), (e) => {
    assert.equal(e.name, "TypeError");
    return true;
  });
});

test("A-ISLAND-01: scalar bodies (123, \"x\", [], true) are handled WITHOUT throwing", async () => {
  // Contrast with `null`: these pass Object.hasOwn (boxed), so getRequestData
  // returns the raw value (number/string/array) instead of throwing. The full
  // endpoint then fails decrypt on `.encryptedComponentExport` → clean 400.
  // `null` is the lone value that reaches Object.hasOwn and throws.
  for (const body of ["123", '"x"', "[]", "true"]) {
    await assert.doesNotReject(() => getRequestData(postReq(body)), `body ${body} should not throw`);
  }
});

// ---- A-ISLAND-02: malformed/plaintext-smuggling ----
test("A-ISLAND-02: malformed JSON → 400", async () => {
  const r = await getRequestData(postReq("{ not json"));
  assert.ok(r instanceof Response);
  assert.equal(r.status, 400);
});

test("A-ISLAND-02: plaintext slots → 400", async () => {
  const r = await getRequestData(postReq(JSON.stringify({ slots: { default: "x" } })));
  assert.ok(r instanceof Response);
  assert.equal(r.status, 400);
});

test("A-ISLAND-02: plaintext componentExport → 400", async () => {
  const r = await getRequestData(postReq(JSON.stringify({ componentExport: "default" })));
  assert.ok(r instanceof Response);
  assert.equal(r.status, 400);
});

test("A-ISLAND-02: GET missing s/e/p → 400", async () => {
  const r = await getRequestData(new Request(islandUrl, { method: "GET" }));
  assert.ok(r instanceof Response);
  assert.equal(r.status, 400);
});

// ---- A-ISLAND-03: oversized body limit ----
test("A-ISLAND-03: honest oversized body (Content-Length > limit) → 413", async () => {
  const limit = 2048;
  const big = JSON.stringify({ x: "A".repeat(limit * 2) });
  const r = await getRequestData(postReq(big), limit);
  assert.ok(r instanceof Response);
  assert.equal(r.status, 413);
});

test("A-ISLAND-03: streamed body with NO Content-Length over limit → 413 (stream counter backstop)", async () => {
  const limit = 1024;
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(new Uint8Array(limit + 64));
      c.close();
    },
  });
  const req = new Request(islandUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: stream,
    duplex: "half",
  });
  const r = await getRequestData(req, limit);
  assert.ok(r instanceof Response);
  assert.equal(r.status, 413);
});

// ---- A-ISLAND-04: cross-island AAD binding ----
test("A-ISLAND-04: props encrypted for island A do NOT decrypt under island B's AAD", async () => {
  const key = await createKey();
  const blob = await encryptString(key, JSON.stringify({ secret: "A" }), "props:IslandA");

  // Same AAD → succeeds.
  const ok = await decryptString(key, blob, "props:IslandA");
  assert.equal(JSON.parse(ok).secret, "A");

  // Different component id in AAD → GCM auth fails → throws.
  await assert.rejects(() => decryptString(key, blob, "props:IslandB"));
});
