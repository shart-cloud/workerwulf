// P-WL-ISO-002 (resource shared-fate) + P-WL-ISO-003 (cache-state isolation)
//
// One worker module, co-located across isolates via spec.runtime.maxIsolates > 1
// (isolate-0 on :8080, isolate-1 on :8081, … all in ONE workerd process/pod).
// The role is chosen per-request so the SAME module can play aggressor, victim,
// or cache writer/reader depending on which isolate/port you fire it at.
//
// This is the committed, reproducible successor to F-1's ad-hoc kubectl drive.
// It extends F-1 ("V8 isolate boundary gives no MEMORY isolation; the cgroup
// does") along two axes:
//
//   (d) resource shared-fate matrix — does an aggressor in isolate-0 that
//       exhausts memory / pegs CPU / floods sockets degrade or kill a victim
//       in co-located isolate-1, vs. a victim in a separate pod (cgroup)?
//   (c) cache-state isolation — can isolate-1 read a secret that isolate-0
//       wrote to caches.default? (a confidentiality leak, distinct from the
//       resource leak in F-1).
//
// Roles (?role=, default "info"):
//   info        — liveness + runtime snapshot (also used as the victim baseline)
//   victim      — prove alive, do a small allocation, report self-latency
//   aggressor   — &resource=mem|cpu|fd, exhaust the chosen resource
//   cache-write — &key=&secret=, write secret into caches.default under key
//   cache-read  — &key=, attempt to read that key back
//
// Aggressor params: &mb (mem, default 400) &ms (cpu/fd hold window, default 8000)
//                   &n (fd concurrent sockets, default 256) &sink (fd hang target)

const BASE_TEST_ID = "P-WL-ISO-002";

// Module-global so allocations/sockets survive the request return and keep
// resource pressure on while a concurrent victim probe runs against the
// neighbour isolate. (For mem the pod usually OOMs before we ever return.)
const HELD = { blocks: [], sockets: [] };

export default {
  async fetch(request, env, ctx) {
    const started = Date.now();
    const url = new URL(request.url);
    const role = url.searchParams.get("role") || "info";
    const runId = url.searchParams.get("run_id") || env.RUN_ID || crypto.randomUUID();

    const base = {
      test_id: roleTestId(role),
      track: "isolate-boundary",
      timestamp: new Date().toISOString(),
      run_id: runId,
      role,
      // The socket port is the isolate identity (8080=isolate-0, 8081=isolate-1, …).
      isolate_port: url.port || null,
      worker_name: env.WORKER_NAME || "iso-shared-fate",
      hardening_profile: env.HARDENING_PROFILE || "naked",
    };

    try {
      let details;
      switch (role) {
        case "aggressor":
          details = await runAggressor(url, env);
          break;
        case "victim":
          details = runVictim(url);
          break;
        case "cache-write":
          details = await cacheWrite(url);
          break;
        case "cache-read":
          details = await cacheRead(url);
          break;
        default:
          details = runInfo();
      }
      return json({ ...base, result: "ok", details, elapsed_ms: Date.now() - started });
    } catch (error) {
      return json(
        {
          ...base,
          result: "error",
          error_name: error instanceof Error ? error.name : "unknown",
          message: error instanceof Error ? error.message : String(error),
          elapsed_ms: Date.now() - started,
        },
        500,
      );
    }
  },
};

function roleTestId(role) {
  return role === "cache-write" || role === "cache-read"
    ? "P-WL-ISO-003"
    : BASE_TEST_ID;
}

// ── (d) resource shared-fate ───────────────────────────────────────────────

async function runAggressor(url, env) {
  const resource = url.searchParams.get("resource") || "mem";
  switch (resource) {
    case "mem":
      return eatMemory(intParam(url, "mb", 400));
    case "cpu":
      return burnCpu(intParam(url, "ms", 8000));
    case "fd":
      return floodSockets(
        intParam(url, "n", 256),
        intParam(url, "ms", 8000),
        url.searchParams.get("sink") || env.FD_SINK_URL || "",
      );
    default:
      throw new Error(`unknown resource '${resource}' (want mem|cpu|fd)`);
  }
}

// Allocate page-touched memory above the pod's cgroup limit. If the cgroup is the
// real boundary (F-1), the pod OOM-kills here and this never returns; co-located
// isolates die with it, separated pods don't.
function eatMemory(mb) {
  const ONE_MB = 1024 * 1024;
  for (let i = 0; i < mb; i++) {
    const block = new Uint8Array(ONE_MB);
    // Touch one byte per 4 KiB page so the pages are actually committed, not
    // lazily reserved — otherwise the RSS never grows and nothing OOMs.
    for (let j = 0; j < ONE_MB; j += 4096) block[j] = 1;
    HELD.blocks.push(block);
  }
  return { resource: "mem", allocated_mb: mb, note: "returned without OOM" };
}

// Peg the isolate's thread with synchronous work for `ms`. While this spins,
// fire a victim probe at the neighbour isolate and compare its latency to
// baseline — if it spikes, the isolates share a CPU/thread fate.
function burnCpu(ms) {
  const start = Date.now();
  let x = 0;
  while (Date.now() - start < ms) {
    // Defeat dead-code elimination.
    for (let i = 0; i < 1e5; i++) x += Math.sqrt(i) * Math.sin(i);
  }
  return { resource: "cpu", burned_ms: Date.now() - start, checksum: x };
}

// Exploratory: open many concurrent outbound subrequests and hold them open to
// consume connection/descriptor slots. Depends on egress being permitted by the
// hardening profile; under deny-all-egress this just records failures.
async function floodSockets(n, ms, sink) {
  if (!sink) {
    return { resource: "fd", attempted: false, reason: "no sink target (set ?sink= or FD_SINK_URL)" };
  }
  let opened = 0;
  let failed = 0;
  const controller = new AbortController();
  setTimeout(() => controller.abort("fd hold window elapsed"), ms);
  for (let i = 0; i < n; i++) {
    const p = fetch(sink, { signal: controller.signal })
      .then(() => { opened++; })
      .catch(() => { failed++; });
    HELD.sockets.push(p);
  }
  // Give the sockets a beat to establish before reporting.
  await new Promise((r) => setTimeout(r, Math.min(ms, 500)));
  return { resource: "fd", attempted: true, requested: n, hold_ms: ms, opened, failed, sink };
}

function runVictim(url) {
  // Small allocation to prove the isolate can still do work.
  const probe = new Uint8Array(1024 * 1024);
  probe[0] = 42;
  // Time a FIXED compute burst. If this isolate is CPU-throttled (e.g. a
  // co-located neighbour is burning the shared cgroup's CPU quota), the same
  // work takes measurably longer — that elapsed time is the starvation signal.
  // self_latency only captures in-handler time, which is too cheap to show it.
  const iters = intParam(url, "work", 4e7);
  const t0 = Date.now();
  let x = 0;
  for (let i = 0; i < iters; i++) x += Math.sqrt(i);
  const t1 = Date.now();
  // started_at/ended_at are absolute epoch ms so a driver can check whether two
  // concurrent bursts on different isolates actually OVERLAPPED in time (needed
  // to interpret CPU contention — non-overlapping bursts can't contend).
  return {
    alive: true, small_alloc_ok: probe[0] === 42, work_iters: iters,
    work_ms: t1 - t0, started_at: t0, ended_at: t1, checksum: x,
  };
}

// ── (c) cache-state isolation ──────────────────────────────────────────────

// caches.default keys on the request URL. Writer (isolate-0) and reader
// (isolate-1) use the SAME synthetic key URL; if the reader finds the secret,
// the default cache is shared across co-located isolates.
function cacheKeyRequest(key) {
  return new Request(`https://iso-cache.invalid/${encodeURIComponent(key)}`);
}

async function cacheWrite(url) {
  const key = url.searchParams.get("key");
  const secret = url.searchParams.get("secret") || "isolate-0-secret";
  if (!key) throw new Error("cache-write requires ?key=");
  const res = new Response(secret, {
    headers: { "cache-control": "max-age=3600", "content-type": "text/plain" },
  });
  await caches.default.put(cacheKeyRequest(key), res);
  return { op: "write", key, wrote_bytes: secret.length };
}

async function cacheRead(url) {
  const key = url.searchParams.get("key");
  if (!key) throw new Error("cache-read requires ?key=");
  const hit = await caches.default.match(cacheKeyRequest(key));
  if (!hit) return { op: "read", key, found: false, leaked: false };
  const value = await hit.text();
  // If this isolate reads back a key another isolate wrote, that's the leak.
  return { op: "read", key, found: true, value, leaked: true };
}

// ── helpers ────────────────────────────────────────────────────────────────

function runInfo() {
  return {
    alive: true,
    runtime: { date_now: Date.now(), performance_now: performance.now() },
    caches_type: typeof globalThis.caches,
    held_blocks: HELD.blocks.length,
    held_sockets: HELD.sockets.length,
  };
}

function intParam(url, name, fallback) {
  const raw = url.searchParams.get(name);
  if (raw === null) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

function json(body, status = 200) {
  return Response.json(body, { status, headers: { "cache-control": "no-store" } });
}
