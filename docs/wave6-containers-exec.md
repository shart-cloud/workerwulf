# Wave 6 — Cloudflare Containers `exec()` probes (`W-CTR-01…11`)

New probe family targeting **process execution inside Cloudflare Containers** —
<https://developers.cloudflare.com/containers/execute-commands/> — reached from Worker
code via `ctx.container.exec(argv, options)`. The call returns an `ExecProcess` with
`stdin` / `stdout` / `stderr` streams, a `pid`, an `exitCode` promise, `output()` and
`kill()`.

The shape that motivated the wave is the one in the public demo doing the rounds: an
inbound HTTP **request body streamed straight into a process's stdin** (image → ffmpeg
→ WebP), with nothing buffering or inspecting it in between. That is a new kind of edge
in the platform — isolate-confined JavaScript handing attacker-controlled bytes, and
attacker-influenced argv, to a real Linux process.

All Wave 6 probes are tagged `container`, carry benign run-tagged `flag{w-ctr-NN-…}`
canaries, exercise **one** behaviour each, and target only the researcher's own
account. Nothing is written outside `/tmp` and `/srv`; no third-party host is contacted
except the researcher's own `callbackd`.

---

## Why this is a new surface, not more `W-CAP` or `W-RUN`

Every existing Track-1 family asks what the **isolate** can see or reach. This one asks
what a **second sandbox**, reachable from the isolate, hands an attacker.

| | Isolate probes (`W-RUN`, `W-ENV`, `W-NET`) | Capability bindings (`W-CAP-*`) | Containers exec (`W-CTR-*`) |
|---|---|---|---|
| Executes | V8 isolate, no processes | remote service via binding | **local POSIX process** |
| Filesystem | none | none | writable, persistent for container lifetime |
| Egress | `fetch()`, policed, restricted ports | the binding's own path | **ordinary socket layer** — any port, raw TCP, own resolver |
| Lifetime | bounded by the invocation | bounded by the request | **not bounded** — `exec()` has no built-in timeout |
| Secrets | isolate-only, never in a process env | binding-scoped | **process environment**, plus `/proc/1/environ` |
| Identity | n/a | n/a | uid chosen by the **caller** of `exec()` (`user` option) |

The novelty thesis recorded in the `comparison` block on every probe: **on AWS Lambda,
Azure Functions and GCP Cloud Run functions, the container *is* the function sandbox.**
There is no isolate→container process API, so there is no boundary of this kind to
cross and no control that reasons about the function's behaviour which can be sidestepped
by stepping into a second, more permissive sandbox. Serverless Prey's environment-harvest
methodology assumed the function already ran in the container; here it has to be re-asked
one boundary over, and several of its assumptions invert.

### The docs page understates the surface

`@cloudflare/workers-types@4.20260521.1` (`experimental/index.d.ts`, ~L3970–4045) exposes
members of the container handle that the execute-commands page does not mention. They are
in scope for this wave because each is a distinct security primitive:

| Member | Probe | Why it matters |
|---|---|---|
| `inspect()` | W-CTR-01 | container metadata/labels readable from the isolate |
| `snapshotDirectory()` / `snapshotContainer()` + `ContainerStartupOptions.directorySnapshots` / `containerSnapshot` | W-CTR-09 | durable, **transferable** filesystem state; a snapshot handle is plain JSON |
| `interceptOutboundHttp` / `Https` / `Tcp` / `interceptAllOutboundHttp` | W-CTR-10 | reroutes container egress into a Worker — an egress control *and* a MITM primitive |
| `getTcpPort()` | W-CTR-11 | port-addressed channel into the container, with no declaration requirement |
| `enableInternet`, `hardTimeout`, `setInactivityTimeout()` | W-CTR-05, W-CTR-06 | the only documented containment knobs; do they bind exec'd processes? |

---

## Architecture

### The target: `@wulf/container` (`packages/container/`)

A separate Worker (`wulf-container`) owning a container Durable Object, mirroring the
`packages/llamafirewall` layout — it is the repo's only other container package.

- **`CtrTarget`** (`src/index.ts`) — a `DurableObject` with a container attached,
  exposing a JSON-RPC surface over `ctx.container` at `POST /ctr/<op>`. It is
  **deliberately vulnerable**, in the same spirit as Wave 5's `WcVictim`: it
  interpolates caller-supplied strings into `sh -c`, passes caller-supplied
  `env`/`user`/`cwd` through to `exec()`, and streams a caller's request body to a
  process's stdin. The point is to demonstrate the sinks, not to assert about them.
  It extends `DurableObject` directly rather than the `@cloudflare/containers` helper
  because the wave needs raw `start()` options (`enableInternet`, snapshot restore)
  that the helper abstracts away.
- **`InterceptSink`** — a `WorkerEntrypoint` bound to the same Worker. `interceptOutbound*`
  reroutes the container's egress here; it answers with `flag{w-ctr-10-egress-intercepted}`,
  so a container process whose `curl` prints that canary was demonstrably rerouted. No
  shared state is needed to detect interception.
- **Image** (`container/Dockerfile`) — `debian:bookworm-slim` + `ffmpeg`, `curl`,
  `busybox`, `procps`, `iproute2`, `ca-certificates`. An ordinary utility image, not a
  purpose-built attack image: the finding should be about the platform edge, not about
  exotic tooling. `CMD` is `busybox httpd` on :8080, because `exec()` **does not start a
  stopped container** — something must keep it running — and that listener doubles as
  W-CTR-11's declared-port baseline.
- `instance_type = "basic"` (1/4 vCPU, 1 GiB). `dev` (256 MiB) is too small for the
  ffmpeg transcode in W-CTR-03.

### Driving it from `wulf-worker`

```toml
[[services]]
binding = "SVC_CTR"
service = "wulf-container"
```

`Env.SVC_CTR` is **optional** (`SVC_CTR?: Fetcher`), the same pattern as `SVC_WC_VICTIM`
and the `W-CAP-*` bindings, so all 11 probes return `blocked` locally and pre-deploy
instead of throwing. `packages/worker/src/probes/_ctr.ts` holds the shared client
(`ctrCall`, `ctrStdin`, `recOf`, `ctrBlocked`, `CTR_COMPARISON`) — probes contain
analysis, not transport.

### Safety rails

These are what make a deliberately-vulnerable exec surface acceptable to deploy:

- every exec runs under a hard timeout with `kill()` in a `finally` — no probe can leave
  a runaway process. W-CTR-06 exists to observe lifetime and reaps its own process
  explicitly via the `kill_marker` op;
- stdout/stderr are capped at 4 KiB per stream before crossing back into the isolate,
  except in W-CTR-08 where a bounded ramp is the measurement, stops at the first failure,
  and is never repeated or run concurrently;
- stdin payloads are capped at 8 MiB;
- egress targets are supplied by the probe and are only ever the researcher's own
  callback host, loopback, or documented-reserved ranges — one connect each, no scanning;
- W-CTR-07 enumerates privilege; it does not attempt escape. Its write tests clean up
  after themselves;
- W-CTR-05 restores `enableInternet: true` before returning, so it does not leave the
  container in a modified state for the rest of the wave.

---

## Probes

| ID | Target | What it establishes | Severity driver |
|---|---|---|---|
| **W-CTR-01** | `exec()` surface | uid/caps/seccomp, cgroup limits, mounts, tool inventory, network view, and which handle methods exist | informational baseline |
| **W-CTR-02** | argv vs `sh -c` | the same untrusted string is literal through argv and **executes** through the shell hop | `high` when the shell hop executes |
| **W-CTR-03** | request body → stdin | byte-exact round trip (incl. chunked, no `Content-Length`), a real ffmpeg transcode, and a payload that chooses its own demuxer | `high` if the payload reaches a local path |
| **W-CTR-04** | env inheritance | Worker vars/secrets in the process env, caller `env` override (PATH, `LD_PRELOAD`), `/proc/1/environ` harvest | `high` if the harvest survives per-exec env scrubbing |
| **W-CTR-05** | egress | container vs isolate reach: arbitrary ports, raw TCP, DNS, reserved ranges; does `enableInternet: false` bind exec'd processes | `high` on reserved-range reach or egress surviving the disable |
| **W-CTR-06** | process lifetime | does a spawned process outlive the invocation, and a multi-second gap | `medium` if it survives |
| **W-CTR-07** | privilege | default uid, whether the caller can raise it via `user`, writable image paths, setuid inventory | `high` if the caller can escalate to root |
| **W-CTR-08** | `output()` | container-decided stdout volume buffered onto the isolate's memory budget | `medium` if no ceiling within the ramp |
| **W-CTR-09** | snapshots | runtime-written marker persisted across destroy/restore, and carried into a **different** DO instance (with a clean control instance) | `high` if it carries |
| **W-CTR-10** | `interceptOutbound*` | egress rerouted into Worker code, per scheme; whether HTTPS interception raises any TLS error the process could notice | `medium` if TLS is transparent |
| **W-CTR-11** | `getTcpPort()` | declared port, dead-port negative control, and a port stood up by `exec()` and never declared | `medium` if the undeclared port is reachable |

The pairing that carries the wave: **W-CTR-02 supplies code execution, and W-CTR-04/05/06/07/09
each describe what that execution is worth.** Enumerate first (01), then read each later
probe as a blast-radius multiplier on the second one.

---

## Deploy / verify runbook

Wave 6 is **deploy-only**. `wrangler dev` has no container runtime, so `ctx.container` is
absent and every probe correctly reports `blocked` locally — that is the pre-deploy pass
criterion, not a failure.

```bash
# 0. structure only
pnpm -r typecheck
pnpm --filter @wulf/container exec wrangler deploy --dry-run
pnpm --filter @wulf/worker     exec wrangler deploy --dry-run

# 1. build + push the image (~300-400 MB)
#    --network=host is required on the WSL2 dev host: on the default Docker bridge,
#    deb.debian.org resolves AAAA-only with no IPv6 route, so apt fetches every
#    InRelease and then ignores it until the layer fails. See the Dockerfile comment.
cd packages/container
docker build --network=host -t wulf-container:v1 ./container
pnpm exec wrangler containers push \
  registry.cloudflare.com/11caecd272df7dbdcc636034c25b1f1c/wulf-container:v1

# 2. the W-CTR-04 secret canary
pnpm exec wrangler secret put WULF_CTR_SECRET   # value: flag{w-ctr-04-worker-secret}

# 3. deploy the target FIRST — wulf-worker's service binding requires it to exist
pnpm exec wrangler deploy
cd ../worker && pnpm exec wrangler deploy

# 4. run the family
RUN=wave6-$(date +%s)
for n in 01 02 03 04 05 06 07 08 09 10 11; do
  curl -s "https://wulf-worker.<subdomain>.workers.dev/probe/W-CTR-$n?run_id=$RUN" | jq .
done
```

Pass criteria:

- every probe returns a verdict other than `blocked` with populated `details` — a
  `blocked` result **after** deploy means the binding or the container never came up;
- `W-CTR-03` reports `byte_exact_round_trip: true` and `ffmpeg_produced_webp: true`;
- `W-CTR-09`'s control instance reports `control_instance_leaked_marker: false` — without
  that, a `carried: true` result proves nothing;
- `W-CTR-11` reports `dead_port_answered: false` — a dead port that answers would mean the
  Fetcher is not bound to this container;
- re-running `W-CTR-01` afterwards shows a clean process table (no leftover `sleep` or
  `httpd` from W-CTR-06 / W-CTR-11).

## Deploy-verify results (2026-07-30, run `wave6-20260730`)

Image `wulf-container:v1` (548 MB, digest `sha256:dfd95e7b…`), `instance_type = "basic"`,
worker version `0ba46a58`, container worker version `a9273487`. Colo `iad21`.
All 11 probes ran against the deployed stack; **10 `accessible`, 1 `blocked`**.

| ID | Result | Sev | What the run established |
|---|---|---|---|
| W-CTR-01 | accessible | info | Container runs as **uid 0**, `Seccomp: 0`, `CapEff: 000001ffffffffff` (full set), `NoNewPrivs: 0`, 1 vCPU / ~1.2 GB. `exec`, `getTcpPort`, `snapshot*`, `interceptOutboundHttp/Https`, `interceptAllOutboundHttp`, `setInactivityTimeout`, `destroy`, `signal` are functions; **`inspect()` and `interceptOutboundTcp()` are typed but not implemented** (`c.inspect is not a function`). |
| W-CTR-02 | accessible | **high** | argv is literal — no glob, no redirect, no chaining. The same string through `sh -c` executes and returns `uid=0(root)`. The sink is confirmed end-to-end from an HTTP request. |
| W-CTR-03 | accessible | medium | 256 KiB **byte-exact** through stdin (SHA-256 in == out); a chunked `ReadableStream` with **no `Content-Length`** is also byte-exact; ffmpeg emits a real WebP (`52494646…57454250`, 2836 B, ~2.9 s). On auto-probed input the **payload selected the concat demuxer** and asked for `/etc/hostname` — ffmpeg's own `-safe` default refused it (`Unsafe file name '/etc/hostname'`). The reach exists; the parser's default is what stops it. |
| W-CTR-04 | accessible | **high** | exec'd processes get a **clean** env (no Worker vars) — but `/proc/1/environ` returns `WULF_CTR_SECRET`, `WULF_CTR_VAR`, and Cloudflare's own `CLOUDFLARE_DURABLE_OBJECT_ID`, `DEPLOYMENT_ID`, `APPLICATION_ID`, `NODE_ID`, `PLACEMENT_ID`, `LOCATION=iad21`, `REGION=ENAM`. Per-exec env hygiene is therefore **not** sufficient. The caller can also override `PATH` and set `LD_PRELOAD`. |
| W-CTR-05 | accessible | medium | Container HTTP egress works (own callback, 200). **Raw TCP to port 22 connects** (`connect=0.0116` then an sshd banner) — a port the isolate's `fetch()` will not open; 443 likewise; own DNS resolver works. **No** link-local (`169.254.169.254`) or foreign RFC1918 reach. `enableInternet: false` **does** bind exec'd processes — egress stopped. Isolate control: callback 200, link-local 403. |
| W-CTR-06 | accessible | medium | A detached process **survives the spawning request and a 7.5 s multi-request gap** (`sh` loop, pid visible in a later invocation's process table). Reaped by the probe's own pid-targeted cleanup, confirmed by a follow-up `ps`. |
| W-CTR-07 | accessible | medium | Default identity is **root**; `/srv` **and `/usr/bin` are writable**; 8 setuid binaries; `ptrace_scope` knob absent. `user: "nobody"` and `user: "root"` were **not honoured** (only `user: "0"` resolved) — so the option is not a usable privilege-reduction control here. `USERNS: user:[4026531837]` is the **initial** user namespace, and `/dev` carries `kvm`, `vhost-net`, `vsock`, `mem`, `vda–vdd` — i.e. this is a guest VM, and the microVM, not the container, is the isolation boundary. |
| W-CTR-08 | accessible | low | 1 MB → 96 MB buffered through `output()` into the isolate successfully (96 MB in 16.8 s); **192 MB fails cleanly** with `Memory limit exceeded before EOF.` A ceiling exists and is enforced with a real error rather than a silent truncation or an opaque isolate death. |
| W-CTR-09 | **blocked** | info | `snapshotDirectory()` and `snapshotContainer()` are callable but both return `internal error; reference = …`. The runtime marker was written successfully, so the failure is the snapshot API itself — **typed and exposed but not functional on this account**. No persistence or cross-instance carry could be demonstrated. |
| W-CTR-10 | accessible | info | `interceptOutboundHttp` **works** — the container's `curl http://example.com/` received the Worker sink's canary. `interceptAllOutboundHttp` likewise. **HTTPS interception is not transparent**: curl reported `SSL certificate problem: self-signed certificate in certificate chain`, so TLS authenticity held and the process could detect it. `interceptOutboundTcp` is not implemented. |
| W-CTR-11 | accessible | medium | Declared port 8080 reachable with the image canary; dead port **correctly refused** (`The container is not listening in the TCP address 10.0.0.1:8099` — which also reveals the container's own address); **a port stood up by `exec()` and declared nowhere (9091) is reachable through `getTcpPort()`**. |

### Reading

The wave's centre of gravity is the pairing it was designed around. **W-CTR-02 gives
code execution from request data**, and W-CTR-04/05/06/07/11 each price it: the process
is root, can read the container's real environment through PID 1, has a general-purpose
socket layer the isolate does not, outlives the request that created it, and can open
new Worker-reachable ports. None of those is a platform vulnerability on its own — every
one is documented or reasonable behaviour — but together they describe a blast radius
that a Worker author reading only the execute-commands page would not expect.

Three findings cut the other way, and are worth stating as clearly as the exposures:
`enableInternet: false` genuinely binds exec'd processes, `output()` enforces a real
memory ceiling with a real error, and HTTPS interception does not defeat certificate
validation. The platform's containment story is better than the capability inventory in
W-CTR-01 suggests, largely because the container is a **microVM guest** — root with full
caps inside it is not root on a shared host.

Two API-surface facts are worth recording on their own: `inspect()` and
`interceptOutboundTcp()` are in the shipped types but absent at runtime, and the snapshot
pair is present at runtime but returns internal errors. Typed surface is not, on this
platform, evidence of an available capability.

### Probe corrections made during the run

Recorded because the first pass produced wrong data, not merely slow data:

1. **A destroy/restart wedged the shared container DO.** Requests to one Durable Object
   are serialized, so W-CTR-05's restart stalled W-CTR-06/07/08 into timeouts. Fixed by
   bounding `destroy()` with a race (`destroyBounded`) and moving the two destructive
   probes (05, 09) onto **their own instances**.
2. **The TCP-connect classifier anchored on the wrong position**, so port 22 — which had
   plainly connected — was reported `UNKNOWN`. It now matches `connect=` anywhere in the
   output. This flipped W-CTR-05's raw-TCP finding from false to true.
3. **`pkill -f <marker>` matches the killing shell's own argv**, so W-CTR-06's cleanup
   rail killed itself and never reaped the target. Replaced with a pid-targeted
   `kill_pid` op plus an independent `ps` confirmation.
4. **W-CTR-05 probed `10.0.0.1` as "RFC1918"** — which W-CTR-11's dead-port error
   revealed to be the container's *own* address. Retargeted to `192.168.0.1`, with the
   self-address kept as a separate, honestly-labelled row.
5. **W-CTR-10 credited a failed `interceptOutboundTcp` install with an interception**
   inherited from the still-active HTTP rule. Interception is now only counted when the
   install succeeded.

### Operational note

The target Worker is gated by a shared secret (`WULF_CTR_AUTH`, `x-wulf-ctr-auth`) in
addition to `workers_dev = false`. That gate exists because the first deploy enabled a
`workers.dev` route by default and the arbitrary-`sh -c` endpoint was briefly reachable
from the internet; it was confirmed executing a command from an unauthenticated public
request and closed immediately. Routing is not an access control for this Worker.

## Disclosure

Any cross-tenant-looking result — W-CTR-09 restoring data that was not written by this
account, W-CTR-05 reaching infrastructure outside it — **stops the wave**. Report to
Cloudflare via HackerOne per the project's coordinated disclosure policy before probing
further in that direction.

The 2026-07-30 run produced **no such result**: no link-local or foreign RFC1918 reach,
and the snapshot API never functioned, so no cross-instance carry was demonstrated.
Nothing in this wave is currently at the disclosure threshold; the findings are a
blast-radius characterisation of documented behaviour, not a platform break.
