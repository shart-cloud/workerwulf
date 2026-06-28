# Isolate-boundary shared-fate probes

Successor to **F-1** (`../../RESULTS.md`), which proved the V8 isolate boundary
provides no *memory* isolation between co-located isolates — the container cgroup
does. F-1 was run ad-hoc; this directory makes it reproducible and extends it
along two axes the F-1 "Open follow-ons" list called for:

- **(d) P-WL-ISO-002 — resource shared-fate matrix.** Does an aggressor in
  isolate-0 that exhausts a resource degrade/kill a victim in co-located
  isolate-1 (one pod, V8-isolate boundary) vs. a victim in a separate pod
  (cgroup boundary)? Resources: `mem` (the F-1 OOM, now committed), `cpu`
  (starvation), `fd` (socket flood, exploratory).
- **(c) P-WL-ISO-003 — cache-state isolation.** Can isolate-1 read a secret
  isolate-0 wrote to `caches.default`? A confidentiality leak, distinct from the
  resource leak in F-1.

## Files

- `iso-shared-fate.js` — single worker module, role-switched per request
  (`?role=aggressor|victim|cache-write|cache-read|info`). The **source of truth**;
  the driver inlines it into manifests so there's no duplicated copy to drift.
- `iso-shared-fate.sh` — generates SandboxWorker manifests from the probe,
  applies them, drives the matrix from in-cluster ephemeral curl pods, prints a
  summary.

## Arrangements (held equal except the boundary)

| Worker | `maxIsolates` | Boundary under test |
|---|---|---|
| `iso-shared-fate-colo` | 2 | isolate-0 (`:8080`) & isolate-1 (`:8081`) in **one** pod / 256Mi cgroup → V8-isolate boundary |
| `iso-shared-fate-sep-a` + `iso-shared-fate-sep-v` | 1 each | two pods / two cgroups → container boundary |

## Usage

```bash
./iso-shared-fate.sh up            # apply + wait for rollout
./iso-shared-fate.sh cache         # (c) write on isolate-0, read on isolate-1
./iso-shared-fate.sh mem           # (d) 400MiB OOM, read restartCount/OOMKilled
./iso-shared-fate.sh cpu           # (d) two concurrent bursts; check time-overlap
./iso-shared-fate.sh enforce       # is cpu.max enforced? burst at 200m/500m/2000m
./iso-shared-fate.sh fd <sink>     # (d) socket flood (needs egress; exploratory)
./iso-shared-fate.sh all           # cache + mem + cpu
./iso-shared-fate.sh enforce-down  # cleanup for `enforce`
./iso-shared-fate.sh down          # cleanup
./iso-shared-fate.sh render <dir>  # just emit manifests, no cluster
```

## Reading the results

- **cache (c):** co-located isolate-1 read returns `leaked:true` ⇒ `caches.default`
  is shared across isolates in one process. The separated control must return
  `found:false`.
- **mem (d):** co-located → both isolates' pod shows `restartCount` bump and
  `OOMKilled`; the isolate-1 victim body is empty/restarted (died with the pod).
  Separated → only the aggressor pod restarts; the victim still serves
  `{"alive":true}`. (This is the committed reproduction of F-1.)
- **cpu (d):** two identical bursts are fired concurrently on the two isolates.
  Co-located → `overlap ≈ 0` (the bursts run one-after-the-other: a synchronous
  CPU-bound isolate monopolises the single workerd execution thread, so the
  neighbour can't start until it finishes) ⇒ CPU shared fate via serialization.
  Separated → `overlap ≈ full burst` (two processes run truly in parallel).
- **enforce:** sanity check that the CPU cgroup quota actually throttles here —
  the same burst at `cpu.max` 0.2 / 0.5 / 2.0 core should be proportionally
  slower (≈3000 / 1220 / 628 ms). If all three were equal the quota wouldn't be
  biting and the `cpu` result couldn't be read as contention.

Caveats: `fd` depends on egress and is exploratory under `naked`; under
`deny-all-egress` it records failures rather than pressure. Timing (`cpu`)
must be read on real workerd (this cluster), not `wrangler dev`, whose host
clock makes timing meaningless. The serialization result is specific to
*synchronous* CPU work; an aggressor that awaits I/O would yield the thread.
