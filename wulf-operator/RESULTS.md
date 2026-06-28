# wulf-operator research results

Findings from running probes across the wulf-operator hardening/isolation ladder
on a self-hosted workerd cluster. This is the output side of `platform_prd.md`
(esp. Track 5, the hardening differential — "what does Cloudflare actually add on
top of open-source workerd?").

**Environment:** Talos cluster (`admin@talos-cluster`, 2 amd64 nodes), Cilium CNI,
Tetragon v1.7.0 (BPF-LSM enabled), wulf-operator 0.4.0. workerd
`1.20260521.1` (`ghcr.io/jlgore/wulf-operator-workerd:0.1.0`).

**Two boundaries under test.** "Isolation" splits into two independent axes, and
the operator can dial each:

- **OS / container boundary** (workerd process ↔ host/cluster): the hardening
  profile ladder — `naked` → `seccomp-baseline` → `deny-all-egress`
  (NetworkPolicy) → `traced-syscalls` (Tetragon observe) → `bpf-lsm` (Tetragon
  LSM enforce, deny egress/exec/ptrace).
- **Isolate boundary** (isolate ↔ co-located isolate in one workerd process):
  exercised with `spec.runtime.maxIsolates > 1` vs. separate pods.

---

## F-1 — The V8 isolate boundary provides no memory isolation; the cgroup does

**Status:** deploy-verified 2026-06-26.
**Question (PRD Track 3 / Track 5):** co-located isolates share one workerd
process — does the V8 isolate boundary isolate resources between tenants, or does
one isolate's behaviour affect a neighbour?

**Method.** One probe script, role chosen by `?role=aggressor|victim`. The
aggressor allocates 400 MiB of page-touched `Uint8Array` into a pod with
`limits.memory: 256Mi`; the victim only proves it is alive and can still make a
small allocation. Run under two arrangements, holding everything else equal:

- **Co-located:** one `SandboxWorker` with `maxIsolates: 2` → two isolates in one
  pod (aggressor on isolate-0 `:8080`, victim on isolate-1 `:8081`), sharing one
  process and one 256Mi memory cgroup.
- **Separated:** two `SandboxWorker`s → two pods, two cgroups.

Probes were driven from in-cluster ephemeral curl pods against each Service.

**Result.**

| Arrangement | Boundary between A & V | Aggressor | Victim |
|---|---|---|---|
| Co-located (1 pod) | V8 isolate only | pod `OOMKilled`, exit 137, restartCount 1 | **died with it** — same pod restarted |
| Separated (2 pods) | container cgroup | own pod `OOMKilled`, restartCount 1 | **survived** — restartCount 0, still served `{"alive":true}` |

The V8 isolate boundary isolated nothing: the aggressor in isolate-0 took the
whole pod (and so isolate-1) down. The container cgroup did isolate: the same
aggressor in a separate pod left the victim untouched.

**Tracing dimension (same event, `traced-syscalls` profile).** The
operator-attached `workerd-iso-colo-tracing` policy observed the attack at the OS
level while nothing blocked it:

```
pod:       workerd-iso-colo-…
binary:    /usr/local/bin/workerd
function:  __x64_sys_mmap
policy:    workerd-iso-colo-tracing
action:    KPROBE_ACTION_POST      # observe, not block
```

**Interpretation.** The workerd isolate boundary is a *correctness* boundary, not
a *resource/tenancy* boundary — at least for memory, in open-source workerd,
which sets no per-isolate memory cap. Resource isolation between co-located
tenants comes from the container cgroup, and visibility comes from Tetragon. This
is a concrete piece of the "what CF adds" thesis: Cloudflare's platform must add
per-isolate resource accounting/limits that OSS workerd lacks (otherwise one
tenant could OOM its co-tenants). Note the OS hardening profiles
(seccomp/netpol/bpf-lsm) are orthogonal — none of them touch this axis.

**Reproduce.** `maxIsolates` rendering: operator 0.4.0
(`config/samples/wulf_v1alpha1_sandboxworker_isolates.yaml`). Aggressor/victim
manifests and the in-cluster `kubectl run curlimages/curl … --attach` drive are
in the branch history; fire `?role=aggressor&mb=400` at a 256Mi-limited worker
and read `restartCount` / `lastState.terminated.reason` on the target pod(s).

**Open follow-ons:** (a) does a per-isolate V8 heap cap (if workerd exposes one)
change the outcome, or only convert OOM-kill into in-isolate `RangeError`?
(b) timing covert channel between co-located isolates; (c) shared Cache API /
compilation-cache state across isolates — **addressed in F-3 below**.

---

## F-2 — The isolate boundary provides no resource isolation of *any* kind; the failure mode is set by the cgroup, and differs per resource

**Status:** deploy-verified 2026-06-26.
**Question (F-1 follow-on (d)):** F-1 showed co-located isolates share *memory*
fate. Is that specific to memory, or do other resources (CPU) share fate too?

**Method.** Committed, reproducible successor to F-1's ad-hoc kubectl drive:
`probes/isolate/iso-shared-fate.js` (one role-switched worker module) + a driver
`probes/isolate/iso-shared-fate.sh` that renders the manifests from the probe,
applies the same two arrangements as F-1 (co-located `maxIsolates: 2` in one
256Mi pod; separated = two pods), and drives the matrix from in-cluster curl
pods. For CPU, the worker times a fixed compute burst and returns absolute
`started_at` / `ended_at` epoch ms, so the driver can fire two bursts
concurrently and check whether they actually **overlapped** in time — the real
contention signal. (A first pass that compared `work_ms` alone was misleading:
two co-located bursts each report their own throttled time and look identical to
solo even when they ran one-after-the-other.)

**Result.**

| Resource | Co-located (one pod, V8 isolate boundary) | Separated (two pods, cgroup) |
|---|---|---|
| **Memory** | isolate-0 OOMs → pod `OOMKilled`, restart 0→1; isolate-1 **died with it** | aggressor pod restart 0→1; victim **restart 0, still `{"alive":true}`** |
| **CPU** | two concurrent bursts ran **sequentially** — `overlap = 0 ms`, total wall ≈ **2460 ms** (1239 + 1220) | two concurrent bursts ran **in parallel** — `overlap ≈ 1175 ms` (full burst), total wall ≈ **1182 ms** |

Supporting check (`… enforce`): the CPU cgroup quota *is* enforced — the same
single burst at `cpu.max` of 0.2 / 0.5 / 2.0 core took ≈3000 / 1220 / 628 ms
(perfectly proportional; full one-core time ≈628 ms).

**Interpretation.** Both resources share fate when co-located; the *mechanism*
differs. Memory reproduces F-1 (the shared cgroup OOM-kills the whole pod). CPU
shares fate via **serialization**, not throttling: a synchronous CPU-bound
isolate monopolizes the single workerd execution thread, so a co-located
neighbour's request cannot even start until the aggressor's loop finishes
(`overlap = 0`; the neighbour's `started_at` is 2 ms *after* the aggressor's
`ended_at`). Two isolates in **separate** workerd processes run genuinely in
parallel (`overlap ≈ full burst`). Note this is the synchronous-CPU case;
I/O-bound work that awaits would yield the thread and interleave.

> **Correction.** An earlier pass concluded "no CPU shared fate" because the two
> co-located bursts each clocked ≈1220 ms, the same as solo. That was an artifact:
> they were *serialized*, so each still ran alone at the 0.5-core-throttled rate —
> and 1220 ms was itself the *throttled* time (the `enforce` test shows full speed
> is ≈628 ms), not "full single-core speed" as first written. The timestamp
> overlap check is what exposed it.

So the unifying statement is sharper than F-1: **the V8 isolate boundary provides
no resource isolation of any kind — not memory, not CPU.** Co-located isolates
share both the memory cgroup (→ shared OOM) *and* the execution thread (→ a
CPU-bound tenant stalls all co-tenants — a noisy-neighbour/DoS property stronger
than throttling). Isolation comes only from running in separate
processes/pods/cgroups. The "what CF adds" thesis extends: Cloudflare must supply
**per-isolate** resource accounting *and* preemptive CPU scheduling, because
co-located OSS workerd isolates get neither.

**Reproduce.** `probes/isolate/iso-shared-fate.sh up && … mem && … cpu && … enforce`
(see `probes/isolate/README.md`). `fd` (socket-flood) is implemented but left
exploratory — it needs egress and is meaningless under `deny-all-egress`.

**Open follow-ons:** does an async/I/O-yielding aggressor interleave with its
co-tenant (confirming the serialization is specific to synchronous CPU)? The
per-isolate V8 heap-cap question (F-1 (a)) is still open and is now blocked on a
CRD/render knob the operator doesn't expose.

---

## F-3 — There is no Cache API to leak: OSS workerd ships the binding surface but no cache backend

**Status:** deploy-verified 2026-06-26.
**Question (F-1 follow-on (c)):** can a co-located isolate read another isolate's
`caches.default` entries (a cross-tenant confidentiality leak)?

**Method.** Same harness. `role=cache-write` puts a canary secret into
`caches.default` under a key on isolate-0 (`:8080`); `role=cache-read` reads the
same key from isolate-1 (`:8081`). Separated pods as control.

**Result.** Every `caches.default` access — write *and* read, on every isolate,
in both arrangements — throws:

```
{"role":"cache-write","result":"error","error_name":"Error","message":"No Cache was configured"}
```

`typeof globalThis.caches` is `"object"` (the binding surface exists), but
`.default.put` / `.match` throw `No Cache was configured`.

**Interpretation.** The intended leak test is **moot**: in OSS workerd the Cache
API has no backing store unless the worker config wires `cacheApiOutbound` to a
cache service, which the operator does not render. So cross-isolate cache-state
isolation is **not a workerd-level property at all** — the Cache API is entirely
platform-provided. This is itself a clean piece of the "what CF adds" thesis,
parallel to F-1/F-2: Cloudflare supplies the Cache API *backend* (and with it,
whatever cross-tenant namespacing it enforces); open-source workerd ships only
the `caches` global and errors on use.

A meaningful isolation test only becomes possible *after* a backend is wired, and
even then "isolation" would be a property of that `cacheApiOutbound` service (one
shared service ⇒ shared by construction), not of the V8 isolate boundary.

**Reproduce.** `probes/isolate/iso-shared-fate.sh cache`.

**Open follow-ons:** add a `cacheApiOutbound` cache service to the operator's
workerd render, then re-probe to characterize the backend's cross-isolate
namespacing; compilation-cache sharing across isolates remains unprobed.
