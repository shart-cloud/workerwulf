# wulf-operator operator foundation

This is a manual operator foundation, not a generated kubebuilder scaffold yet.
The current slice gives us:

- `api/v1alpha1` Go structs for `SandboxWorker` and `HardeningProfile`.
- CRD manifests under `config/crd`.
- `cmd/wulf-operator`, a controller-runtime manager with a
  `SandboxWorker` reconciler.
- A deterministic renderer that turns an inline-script `SandboxWorker` into:
  - `ConfigMap` containing `workerd.capnp` and `worker.js`
  - `Deployment`
  - `Service`
- Namespaced `HardeningProfile` resolution for each `SandboxWorker`.
- Tests for rendering and security-context behavior.

The renderer intentionally supports only `spec.script.inline` right now. That
matches the proof-of-life scope and keeps the contract narrow before the real
controller watches ConfigMap and Git-backed scripts.

## Validate

```bash
cd wulf-operator/operator
GOCACHE=/tmp/wulf-operator-go-build go test ./...
go run ./cmd/wulf-operator-render
kubectl kustomize config/crd
kubectl kustomize config/default
```

## Build

```bash
docker build -f wulf-operator/operator/Dockerfile -t ghcr.io/jlgore/wulf-operator:0.1.0 wulf-operator/operator
```

## Install and run a SandboxWorker

From the repository root:

```bash
kubectl apply -f wulf-operator/deploy/poc/namespace.yaml
kubectl apply -k wulf-operator/operator/config/default
```

The manager deployment references `ghcr.io/jlgore/wulf-operator:0.1.0`
and starts workers with `ghcr.io/jlgore/wulf-operator-workerd:0.1.0`. Build and
push those images first when testing an unpublished change.

Apply the hardening profile before the worker that references it:

```bash
kubectl apply -f wulf-operator/deploy/profiles/naked.yaml
kubectl apply -f wulf-operator/operator/config/samples/wulf_v1alpha1_sandboxworker.yaml
```

For the restricted baseline:

```bash
kubectl apply -f wulf-operator/deploy/profiles/seccomp-baseline.yaml
kubectl apply -f wulf-operator/operator/config/samples/wulf_v1alpha1_sandboxworker_seccomp_baseline.yaml
```

For the built-in egress-deny profile, apply the profile and point a
`SandboxWorker` at `spec.hardening.profile: deny-all-egress`:

```bash
kubectl apply -f wulf-operator/deploy/profiles/deny-all-egress.yaml
kubectl -n wulf-system patch sandboxworker workerd-rt-001 \
  --type merge \
  -p '{"spec":{"hardening":{"profile":"deny-all-egress"}}}'
```

Check status and rendered resources:

```bash
kubectl -n wulf-system get hardeningprofiles,sandboxworkers,pods,svc,networkpolicies
kubectl -n wulf-system describe sandboxworker workerd-rt-001
```

If the named `spec.hardening.profile` is missing from the `SandboxWorker`
namespace, the reconciler sets `status.phase: Failed` with a
`Ready=False,Reason=HardeningProfileNotFound` condition and does not create or
update the worker deployment.

## Current reconciliation scope

The reconciler uses server-side apply with field owner
`wulf-operator` and creates/updates:

- `ConfigMap`
- `Deployment`
- `Service`
- `NetworkPolicy`, when requested by the resolved `HardeningProfile`
- `TracingPolicyNamespaced` (Tetragon), when requested by the resolved
  `HardeningProfile`
- `SandboxWorker.status`

The reconciler resolves `spec.hardening.profile` as a namespaced
`HardeningProfile` object before rendering. The resolved profile fields drive
the pod security context, and `HardeningProfile` create/update/delete events
reconcile matching `SandboxWorker` objects in the same namespace:

- `naked`: no container security context, preserving the intentionally noisy
  research baseline.
- `seccomp-baseline`: `RuntimeDefault` seccomp, `runAsNonRoot`, no privilege
  escalation, and all Linux capabilities dropped.
- `deny-all-egress`: the `seccomp-baseline` pod security context plus an
  operator-managed `NetworkPolicy` selecting only that worker pod and denying
  all egress.

The supported `spec.networkPolicyRef` value is currently `deny-all-egress`.
Any other value sets `SandboxWorker.status.phase: Failed` with a
`RenderFailed` condition, so unsupported policy names fail closed instead of
silently rendering an unprotected pod.

A `HardeningProfile` may also set `spec.tetragonPolicyRef`. The only supported
value is `workerd-syscalls`, which makes the operator render a per-worker
`TracingPolicyNamespaced` (`<worker>-tracing`). The policy is scoped by
`podSelector` to that worker's pods and by `matchBinaries` to the workerd
binary, tracing `openat`/`connect`/`execve`/`mmap`. It carries an owner
reference to the `SandboxWorker`, so it is garbage-collected with the worker.
Like `networkPolicyRef`, an unsupported value fails closed with `RenderFailed`.
The policy is applied as an unstructured object resolved at runtime, so it only
requires the Tetragon CRDs when a profile actually opts in; the kprobe call
names are x86_64-specific. See `deploy/profiles/traced-syscalls.yaml` and
`config/samples/wulf_v1alpha1_sandboxworker_traced.yaml`.

A `HardeningProfile` may additionally set `spec.tetragonEnforceRef`, which is
orthogonal to `tetragonPolicyRef`: tracing only observes, enforcement denies. The
only supported value is `bpf-lsm-deny`, which renders a second per-worker
`TracingPolicyNamespaced` (`<worker>-enforce`) using Tetragon BPF-LSM hooks
(`spec.lsmhooks`: `socket_connect`, `bprm_check_security`, `ptrace_access_check`)
for the workerd binary, each with `action: Override` returning `-EPERM`. A denied
operation fails in place while the worker keeps running, so a probe can observe
and report the denial. BPF-LSM hooks return access decisions natively, so Override
is reliable without depending on the kernel error-injection allowlist (the reason
this uses `lsmhooks` rather than a kprobe on the `security_*` functions), and the
hook names are architecture-independent. The hook set covers only operations
workerd should never perform; `file_open` is deliberately excluded, since a
blanket file deny scoped to the workerd binary would break workerd's own file
access — meaningful file enforcement needs path-scoped selectors and is a
follow-up. This was verified on a Talos v1.7.0 Tetragon cluster with BPF-LSM
enabled (`socket_connect` Override blocked egress, including DNS, while the pod
stayed `Running`); on a cluster without BPF-LSM the policy applies but does not
block. Like the other refs it is scoped by `podSelector`/`matchBinaries`,
owner-referenced for GC, and fails closed with `RenderFailed` on an unsupported
value. See `deploy/profiles/bpf-lsm.yaml` and
`config/samples/wulf_v1alpha1_sandboxworker_bpf_lsm.yaml`.

## Next controller step

When `kubebuilder` or `controller-gen` is available, this module can be promoted
to a controller-runtime project without changing the public CRD shape:

1. Replace the manually maintained CRD and deepcopy files with generated output.
2. Add ConfigMap and Git-backed script sources.
3. Watch the rendered `TracingPolicyNamespaced` (an `Owns` on the unstructured
   kind) so out-of-band edits reconcile, and add non-x86_64 kprobe variants.
4. Decide whether missing-profile failures should leave existing deployments in
   place or actively scale/delete them.
