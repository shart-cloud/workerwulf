# wulf-local operator foundation

This is a manual operator foundation, not a generated kubebuilder scaffold yet.
The current slice gives us:

- `api/v1alpha1` Go structs for `SandboxWorker` and `HardeningProfile`.
- CRD manifests under `config/crd`.
- A deterministic renderer that turns an inline-script `SandboxWorker` into:
  - `ConfigMap` containing `workerd.capnp` and `worker.js`
  - `Deployment`
  - `Service`
- Tests for rendering and security-context behavior.

The renderer intentionally supports only `spec.script.inline` right now. That
matches the proof-of-life scope and keeps the contract narrow before the real
controller watches ConfigMap and Git-backed scripts.

## Validate

```bash
cd wulf-local/operator
go test ./...
go run ./cmd/wulf-local-render
kubectl kustomize config/crd
```

## Next controller step

When `kubebuilder` or `controller-gen` is available, this module can be promoted
to a controller-runtime project without changing the public CRD shape:

1. Add generated deepcopy methods for `api/v1alpha1`.
2. Add a `SandboxWorkerReconciler`.
3. Replace the sample CLI with reconcile calls into `internal/render`.
4. Create/update the rendered `ConfigMap`, `Deployment`, and `Service`.
5. Add owner references and status updates.
