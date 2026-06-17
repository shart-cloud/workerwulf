import type { Probe } from "./index.js";
import { base, harvestIslandBlobs, islandPost } from "./_helpers.js";

/**
 * A-ISLAND-04 — Cross-island state leakage / ciphertext confusion.
 *
 * Server-island props are AES-GCM encrypted with additionalData (AAD) bound to
 * the component id: `props:${componentId}` (core/encryption.ts + endpoint.ts).
 * That binding should make island A's encrypted props undecryptable when
 * replayed against island B's id. We harvest A's real blobs from a rendered
 * page and replay them to B's endpoint; success (200) would mean the AAD
 * binding is broken → cross-island confusion.
 *
 * Requires the target app to expose two pages each rendering a DIFFERENT
 * server island: /a (island A) and /b (island B).
 */
export const aIsland04: Probe = async ({ env, runId }) => {
  const a = await harvestIslandBlobs(env, "/a");
  const b = await harvestIslandBlobs(env, "/b");

  if (!a || !b) {
    return base({
      test_id: "A-ISLAND-04",
      track: "astro",
      description: "Cross-island ciphertext replay must fail (AAD bound to component id)",
      target: "/_server-islands/[name]",
      result: "error",
      severity: "informational",
      run_id: runId,
      details: { reason: "could not harvest island blobs", a_found: !!a, b_found: !!b },
    });
  }

  if (a.componentId === b.componentId) {
    return base({
      test_id: "A-ISLAND-04",
      track: "astro",
      description: "Cross-island ciphertext replay must fail (AAD bound to component id)",
      target: "/_server-islands/[name]",
      result: "error",
      severity: "informational",
      run_id: runId,
      details: { reason: "/a and /b resolved to the same component id; need two distinct islands", id: a.componentId },
    });
  }

  // Replay island A's encrypted blobs against island B's id.
  const replay = await islandPost(env, b.componentId, {
    encryptedComponentExport: a.e,
    encryptedProps: a.p,
    encryptedSlots: a.s,
  });

  const accepted = replay.status === 200;
  return base({
    test_id: "A-ISLAND-04",
    track: "astro",
    description: "Cross-island ciphertext replay must fail (AAD bound to component id)",
    target: "/_server-islands/[name]",
    result: accepted ? "accessible" : "blocked",
    severity: accepted ? "high" : "informational",
    run_id: runId,
    details: {
      island_a: a.componentId,
      island_b: b.componentId,
      harvest_via: a.via,
      replay_status: replay.status,
      expectation: "400 (props decrypt fails: AAD props:<A> != props:<B>)",
      verdict: accepted ? "AAD binding BROKEN — cross-island prop confusion" : "AAD binding holds",
    },
  });
};
