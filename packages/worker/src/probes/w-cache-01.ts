import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const CACHE_KEY = `https://wulf/signal-run-${Date.now().toString(36)}`;
let writeConfirmed = false;

export const wCache01: Probe = async ({ req, runId }) => {
  const seqValue = new URL(req.url).searchParams.get("seq");
  const seq = seqValue ? parseInt(seqValue, 10) : 0;

  const details: Record<string, unknown> = { seq, cache_key: CACHE_KEY };

  const cache = (caches as { default: Cache; open?(name: string): Promise<Cache> }).default;

  if (seq === 0) {
    const marker = `wulf-cache-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
    try {
      await cache.put(
        new Request(CACHE_KEY),
        new Response(JSON.stringify({ marker, written_at: new Date().toISOString() }), {
          headers: { "content-type": "application/json" },
        }),
      );
      writeConfirmed = true;
      details.phase = "write";
      details.cache_write_success = true;
      details.marker = marker;
    } catch (err) {
      details.phase = "write";
      details.cache_write_success = false;
      details.error = err instanceof Error ? err.message : String(err);
    }
  } else {
    const start = Date.now();
    try {
      const res = await cache.match(new Request(CACHE_KEY));
      const elapsed = Date.now() - start;
      if (res) {
        let body: unknown = null;
        try {
          body = await res.json();
        } catch {
          body = await res.text();
        }
        details.phase = "read";
        details.read_success = true;
        details.latency_ms = elapsed;
        details.cached_body = body;
        details.cache_hit = true;
      } else {
        details.phase = "read";
        details.read_success = false;
        details.cache_hit = false;
        details.latency_ms = elapsed;
        details.note = "Cache miss — entry may have expired or been evicted";
      }
    } catch (err) {
      details.phase = "read";
      details.read_success = false;
      details.error = err instanceof Error ? err.message : String(err);
    }
  }

  const persisted = details.read_success === true;

  return base({
    test_id: "W-CACHE-01",
    track: "worker",
    description:
      "Cross-invocation cache persistence — write on seq=0, read on seq≥1",
    result: persisted ? "accessible" : "blocked",
    severity: persisted ? "low" : "informational",
    run_id: runId,
    details: {
      ...details,
      write_confirmed: writeConfirmed,
      note: persisted
        ? "Cache entry persists across invocations and isolate recycles — available as a covert signaling channel"
        : seq === 0
          ? "Cache write complete, run with --sequential N to test read phases"
          : "Cache entry not found on read — check TTL and cache purging",
    },
  });
};