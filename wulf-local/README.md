# wulf-local proof-of-life slice

This directory is the first implementable slice from `platform_prd.md`. It does
not introduce the operator or CRDs yet. The goal is to prove the research loop:

1. Run one self-hosted `workerd` worker.
2. Return a `@wulf/shared`-compatible `ProbeResult`.
3. Attach host-side Tetragon tracing to the `workerd` process.
4. Store local-only host metadata beside, not inside, the canonical probe result.

## Scope

The PoC probe is `P-WL-RT-001`, implemented in
`probes/runtime/rt-001-syscall-smoke.js`.

It returns:

- `track: "platform"` for compatibility with the existing `ProbeResult` union.
- `tags: ["wulf-local", "runtime-fingerprint", "poc"]` to distinguish it from
  Cloudflare Workers for Platforms probes.
- `details.platform: "wulf-local"` and `details.local_track:
  "runtime-fingerprint"` for cross-platform analysis.

The richer local observation row is defined in `analysis/schema.sql`. That row
wraps the canonical `ProbeResult` JSON and adds pod, node, hardening profile,
workerd version, and host trace fields.

## Local smoke test

The repo already carries `workerd` via the installed Node dependencies. Run:

```bash
bash wulf-local/scripts/run-local-smoke.sh
```

The script starts `workerd` on `127.0.0.1:18080`, requests the probe, validates
the returned JSON shape, and stops the runtime.

To trigger a network syscall during the same request, pass a public HTTP target:

```bash
EGRESS_TARGET=http://93.184.216.34/ bash wulf-local/scripts/run-local-smoke.sh
```

`workerd` defaults global fetch to the configured `internet` service. The PoC
keeps that service at public-address-only behavior so private cluster services
are not silently allowed by the runtime config.

## Kubernetes proof of life

The Kubernetes slice is intentionally manual:

```bash
docker build \
  -f wulf-local/runtime/Dockerfile \
  --build-arg WORKERD_VERSION=1.20260521.1 \
  -t ghcr.io/jlgore/wulf-local-workerd:0.1.0 \
  wulf-local/runtime

docker push ghcr.io/jlgore/wulf-local-workerd:0.1.0
kubectl apply -k wulf-local

# Optional, after Tetragon CRDs are installed:
kubectl apply -f wulf-local/deploy/poc/tetragon-tracingpolicy.yaml

kubectl -n wulf-system port-forward svc/workerd-rt-001 18080:8080
curl -s 'http://127.0.0.1:18080/?run_id=manual-poc' | jq .
curl -s 'http://127.0.0.1:18080/?run_id=manual-poc&egress_target=http://93.184.216.34/' | jq .
```

If Tetragon is installed, `deploy/poc/tetragon-tracingpolicy.yaml` traces
`openat`, `connect`, `execve`, and `mmap` for the `workerd` binary path used by
the PoC image. On non-x86_64 nodes, change the syscall names in that policy
before applying it.

## Acceptance criteria

- The response body validates as a current Workerwulf `ProbeResult`.
- `details.platform` is `wulf-local`.
- `details.local_track` is `runtime-fingerprint`.
- Tetragon emits at least process-start/file activity for the `workerd` pod.
- If `EGRESS_TARGET` or `?egress_target=` is set to a reachable public URL,
  Tetragon also emits a `connect` event for the request.

Validated on Talos on 2026-06-25:

- `workerd-rt-001` returned `P-WL-RT-001` from `wulf-system`.
- Tetragon emitted `process_kprobe` events for `__x64_sys_openat`,
  `__x64_sys_mmap`, and `__x64_sys_connect`.
- The connect event was attributed to `wulf-system/workerd-rt-001` and captured
  destination `93.184.216.34:80`.

## Observation capture

After the PoC deployment and tracing policy are running, capture a joined
observation row:

```bash
RUN_ID=talos-poc-004 bash wulf-local/scripts/capture-talos-poc.sh
```

The script writes:

- `probe-result.json` — the canonical Workerwulf `ProbeResult`.
- `tetragon.log` — recent Tetragon JSON events from the node running workerd.
- `observation.jsonl` — one row matching `analysis/schema.sql`.

To collect from existing files instead:

```bash
node wulf-local/scripts/collect-observation.mjs \
  --probe-result wulf-local/out/talos-poc-004/probe-result.json \
  --tetragon-log wulf-local/out/talos-poc-004/tetragon.log \
  --pod-name workerd-rt-001-cb769bb44-5wvzm \
  --output wulf-local/out/talos-poc-004/observation.jsonl
```

## Deferred

- No operator, CRDs, ProbeTrack, Vector sink, or Parquet writer yet.
- No seccomp or BPF LSM enforcement yet.
- No Durable Object or multi-isolate storage claims yet.
