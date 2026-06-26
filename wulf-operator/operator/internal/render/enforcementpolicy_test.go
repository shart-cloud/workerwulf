package render

import (
	"strings"
	"testing"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-operator/operator/api/v1alpha1"
)

func enforceProfile() *wulfv1alpha1.HardeningProfileSpec {
	return &wulfv1alpha1.HardeningProfileSpec{
		Seccomp:            wulfv1alpha1.SeccompSpec{Type: "RuntimeDefault"},
		TetragonEnforceRef: TetragonEnforceBpfLsmDeny,
	}
}

func TestRenderEnforcementPolicyWhenProfileSetsRef(t *testing.T) {
	worker := sampleWorker()
	objects, err := RenderSandboxWorker(worker, Options{HardeningProfile: enforceProfile()})
	if err != nil {
		t.Fatalf("RenderSandboxWorker() error = %v", err)
	}

	stream := YAMLStream(objects)
	for _, want := range []string{
		"kind: TracingPolicyNamespaced",
		"apiVersion: cilium.io/v1alpha1",
		"name: " + worker.Name + "-enforce",
		// LSM hooks, not syscall entry — and the deny action.
		"security_socket_connect",
		"security_ptrace_access_check",
		"action: Override",
		"/usr/local/lib/node_modules/workerd/bin/workerd",
		"app.kubernetes.io/name: " + worker.Name,
	} {
		if !strings.Contains(stream, want) {
			t.Fatalf("rendered YAML missing %q\n%s", want, stream)
		}
	}

	// An enforcement policy hooks the LSM layer, so it must not carry the
	// architecture-specific syscall-entry kprobes the tracing policy uses.
	if strings.Contains(stream, "__x64_sys_") {
		t.Fatalf("enforcement policy should not use __x64_sys_* syscall kprobes\n%s", stream)
	}
}

func TestRenderEnforcementPolicyResourceScopedToWorker(t *testing.T) {
	worker := sampleWorker()
	resources, err := RenderSandboxWorkerResources(worker, Options{HardeningProfile: enforceProfile()})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	if resources.EnforcementPolicy == nil {
		t.Fatal("EnforcementPolicy = nil, want a rendered policy")
	}
	policy := resources.EnforcementPolicy

	if gvk := policy.GroupVersionKind(); gvk != TracingPolicyGVK {
		t.Fatalf("GVK = %v, want %v", gvk, TracingPolicyGVK)
	}
	if got, want := policy.GetName(), EnforcementPolicyName(worker); got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
	if got, want := policy.GetNamespace(), worker.Namespace; got != want {
		t.Fatalf("namespace = %q, want %q", got, want)
	}

	// Scope to this worker's pods only, otherwise one worker's enforcement
	// policy would deny (and be GC'd against) every workerd in the namespace.
	selector, found, err := unstructuredNestedString(policy.Object, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name")
	if err != nil || !found {
		t.Fatalf("podSelector app name lookup: found=%v err=%v", found, err)
	}
	if selector != worker.Name {
		t.Fatalf("podSelector app name = %q, want %q", selector, worker.Name)
	}
}

func TestRenderEnforcementPolicyAbsentByDefault(t *testing.T) {
	resources, err := RenderSandboxWorkerResources(sampleWorker(), Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	if resources.EnforcementPolicy != nil {
		t.Fatalf("EnforcementPolicy = %v, want nil when profile sets no tetragonEnforceRef", resources.EnforcementPolicy)
	}
}

func TestRenderUnknownTetragonEnforceRefErrors(t *testing.T) {
	profile := &wulfv1alpha1.HardeningProfileSpec{TetragonEnforceRef: "kill-everything"}

	if _, err := RenderSandboxWorker(sampleWorker(), Options{HardeningProfile: profile}); err == nil ||
		!strings.Contains(err.Error(), `unsupported tetragonEnforceRef "kill-everything"`) {
		t.Fatalf("RenderSandboxWorker() error = %v, want unsupported tetragonEnforceRef", err)
	}
	if _, err := RenderSandboxWorkerResources(sampleWorker(), Options{HardeningProfile: profile}); err == nil ||
		!strings.Contains(err.Error(), `unsupported tetragonEnforceRef "kill-everything"`) {
		t.Fatalf("RenderSandboxWorkerResources() error = %v, want unsupported tetragonEnforceRef", err)
	}
}
