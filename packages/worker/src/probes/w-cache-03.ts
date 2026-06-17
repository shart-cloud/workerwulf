import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wCache03: Probe = async ({ runId }) => {
  const details: Record<string, unknown> = {};
  const cache = (caches as { default: Cache }).default;
  const results: Record<string, unknown>[] = [];

  // Test 1: basic key
  const basicKey = `https://wulf/steg-basic/${runId}`;
  results.push(await testRoundTrip(cache, basicKey, "basic text value"));

  // Test 2: base64 in key
  const b64 = btoa(`marker-${Date.now().toString(36)}`);
  const b64Key = `https://wulf/steg-b64/${encodeURIComponent(b64)}`;
  results.push(await testRoundTrip(cache, b64Key, { b64: b64 }));

  // Test 3: very long key (2KB path)
  const longPath = "x".repeat(2048);
  const longKey = `https://wulf/steg-long/${encodeURIComponent(longPath).slice(0, 4096)}`;
  results.push(await testRoundTrip(cache, longKey, "long-key-test"));

  // Test 4: special characters in key
  const specialPath = encodeURIComponent("test!@#$%^&*()_+-=[]{}|;':\",./<>?");
  const specialKey = `https://wulf/steg-special/${specialPath}`;
  results.push(await testRoundTrip(cache, specialKey, "special-chars"));

  // Test 5: unicode in key
  const unicodePath = encodeURIComponent("test-\u{1f600}-\u{2764}-\u{1f389}");
  const unicodeKey = `https://wulf/steg-unicode/${unicodePath}`;
  results.push(await testRoundTrip(cache, unicodeKey, "unicode-test"));

  // Test 6: large value (100KB)
  results.push(
    await testRoundTrip(cache, `https://wulf/steg-large/${runId}`, "x".repeat(102400)),
  );

  // Test 7: try null byte in key (should fail per URL rules)
  try {
    const nullByteKey = `https://wulf/steg-null/${runId}\x00extra`;
    await cache.put(new Request(nullByteKey), new Response("null-test"));
    const match = await cache.match(new Request(nullByteKey));
    results.push({ test: "null_byte_key", write_ok: true, read_ok: match !== undefined });
  } catch (err) {
    results.push({
      test: "null_byte_key",
      write_ok: false,
      error: err instanceof Error ? err.message : String(err),
    });
  }

  // Test 8: query string encoded data
  const queryData = "data=" + btoa("exfil-data-" + Date.now().toString(36));
  const queryKey = `https://wulf/steg-query/${runId}?${queryData}`;
  results.push(await testRoundTrip(cache, queryKey, "query-string-test"));

  const allPassed = results.every((r) => r.write_ok === true && r.read_ok === true);

  return base({
    test_id: "W-CACHE-03",
    track: "worker",
    description:
      "Cache key steganography — test arbitrary data encoding in cache keys",
    result: "informational",
    severity: allPassed ? "low" : "informational",
    run_id: runId,
    details: {
      tests: results,
      total_tests: results.length,
      all_passed: allPassed,
      max_key_length_tested: 4096,
      max_value_size_tested: 102400,
      null_bytes_in_key_supported: results.some(
        (r) => r.test === "null_byte_key" && r.write_ok === true,
      ),
      base64_in_key_supported: results.some(
        (r) => r.test === "base64_key" && r.write_ok === true,
      ),
      note: "Cache keys follow URL rules; values can carry arbitrary data up to 500MB per Cloudflare docs",
    },
    comparison: {
      aws_lambda: "N/A (no equivalent global cache API)",
      azure_functions: "N/A (no equivalent cache API)",
      gcp_functions: "N/A (no equivalent cache API)",
    },
  });
};

async function testRoundTrip(
  cache: Cache,
  key: string,
  value: unknown,
): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = {};
  const testName =
    key.includes("steg-b64") ? "base64_key" :
    key.includes("steg-long") ? "long_key" :
    key.includes("steg-special") ? "special_chars_key" :
    key.includes("steg-unicode") ? "unicode_key" :
    key.includes("steg-large") ? "large_value" :
    key.includes("steg-query") ? "query_string_key" :
    "basic_key";
  result.test = testName;

  try {
    const body =
      typeof value === "string"
        ? value
        : JSON.stringify(value);
    await cache.put(
      new Request(key),
      new Response(body, {
        headers: { "content-type": typeof value === "string" ? "text/plain" : "application/json" },
      }),
    );
    result.write_ok = true;
  } catch (err) {
    result.write_ok = false;
    result.write_error = err instanceof Error ? err.message : String(err);
    return result;
  }

  try {
    const match = await cache.match(new Request(key));
    if (match) {
      const text = await match.text();
      result.read_ok = true;
      result.body_match = text === (typeof value === "string" ? value : JSON.stringify(value));
      result.body_length = text.length;
      result.cache_status = match.headers.get("cf-cache-status");
    } else {
      result.read_ok = false;
      result.error = "Cache miss on read-back";
    }
  } catch (err) {
    result.read_ok = false;
    result.read_error = err instanceof Error ? err.message : String(err);
  }

  return result;
}