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
compilation-cache state across isolates.
