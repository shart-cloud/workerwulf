# wulf-local operator foundation

This is a manual operator foundation, not a generated kubebuilder scaffold yet.
The current slice gives us:

- `api/v1alpha1` Go structs for `SandboxWorker` and `HardeningProfile`.
- CRD manifests under `config/crd`.
- `cmd/wulf-local-operator`, a controller-runtime manager with a
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
cd wulf-local/operator
GOCACHE=/tmp/wulf-local-go-build go test ./...
go run ./cmd/wulf-local-render
kubectl kustomize config/crd
kubectl kustomize config/default
```

## Build

```bash
docker build -f wulf-local/operator/Dockerfile -t ghcr.io/jlgore/wulf-local-operator:0.1.0 wulf-local/operator
```

## Install and run a SandboxWorker

From the repository root:

```bash
kubectl apply -f wulf-local/deploy/poc/namespace.yaml
kubectl apply -k wulf-local/operator/config/default
```

The manager deployment references `ghcr.io/jlgore/wulf-local-operator:0.1.0`
and starts workers with `ghcr.io/jlgore/wulf-local-workerd:0.1.0`. Build and
push those images first when testing an unpublished change.

Apply the hardening profile before the worker that references it:

```bash
kubectl apply -f wulf-local/deploy/profiles/naked.yaml
kubectl apply -f wulf-local/operator/config/samples/wulf_v1alpha1_sandboxworker.yaml
```

For the restricted baseline:

```bash
kubectl apply -f wulf-local/deploy/profiles/seccomp-baseline.yaml
kubectl apply -f wulf-local/operator/config/samples/wulf_v1alpha1_sandboxworker_seccomp_baseline.yaml
```

For the built-in egress-deny profile, apply the profile and point a
`SandboxWorker` at `spec.hardening.profile: deny-all-egress`:

```bash
kubectl apply -f wulf-local/deploy/profiles/deny-all-egress.yaml
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
`wulf-local-operator` and creates/updates:

- `ConfigMap`
- `Deployment`
- `Service`
- `NetworkPolicy`, when requested by the resolved `HardeningProfile`
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

## Next controller step

When `kubebuilder` or `controller-gen` is available, this module can be promoted
to a controller-runtime project without changing the public CRD shape:

1. Replace the manually maintained CRD and deepcopy files with generated output.
2. Add ConfigMap and Git-backed script sources.
3. Add Tetragon policy rendering from the profile refs.
4. Decide whether missing-profile failures should leave existing deployments in
   place or actively scale/delete them.
