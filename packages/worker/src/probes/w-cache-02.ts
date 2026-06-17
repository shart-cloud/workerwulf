import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wCache02: Probe = async ({ runId }) => {
  const marker = `wulf-cross-${Date.now().toString(36)}`;
  const sharedKey = `https://wulf/shared-test/${marker}`;

  const details: Record<string, unknown> = {};
  const cache = (caches as { default: Cache; open?(name: string): Promise<Cache> }).default;

  // Write to default cache
  try {
    await cache.put(
      new Request(sharedKey),
      new Response(JSON.stringify({ marker, source: "prey-worker" }), {
        headers: { "content-type": "application/json" },
      }),
    );
    details.default_cache_write = true;
  } catch (err) {
    details.default_cache_write = false;
    details.default_error = err instanceof Error ? err.message : String(err);
  }

  // Named cache test — caches.open() may not be in the type definitions
  try {
    const cachesAny = caches as unknown as { open(name: string): Promise<Cache> };
    if (typeof cachesAny.open === "function") {
      const named = await cachesAny.open("wulf-shared");
      await named.put(
        new Request(sharedKey),
        new Response(JSON.stringify({ marker, source: "prey-worker-named" }), {
          headers: { "content-type": "application/json" },
        }),
      );
      details.named_cache_write = true;
    } else {
      details.named_cache_write = false;
      details.named_cache_note = "caches.open() not available";
    }
  } catch (err) {
    details.named_cache_write = false;
    details.named_error = err instanceof Error ? err.message : String(err);
  }

  return base({
    test_id: "W-CACHE-02",
    track: "worker",
    description:
      "Cache write with known key — requires second Worker deployment to test cross-worker read visibility",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      marker,
      shared_key: sharedKey,
      ...details,
      note: "This probe writes cache entries. A second Worker script on the same zone is needed to test cross-worker cache visibility. Currently, cache is scoped per-worker-script in the Workers runtime.",
      cross_worker_test_needed: true,
    },
  });
};