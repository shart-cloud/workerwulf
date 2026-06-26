package render

import (
	"strings"
	"testing"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-operator/operator/api/v1alpha1"
)

func tracingProfile() *wulfv1alpha1.HardeningProfileSpec {
	return &wulfv1alpha1.HardeningProfileSpec{
		Seccomp:           wulfv1alpha1.SeccompSpec{Type: "RuntimeDefault"},
		TetragonPolicyRef: TetragonPolicyWorkerdSyscalls,
	}
}

func TestRenderTracingPolicyWhenProfileSetsRef(t *testing.T) {
	worker := sampleWorker()
	objects, err := RenderSandboxWorker(worker, Options{HardeningProfile: tracingProfile()})
	if err != nil {
		t.Fatalf("RenderSandboxWorker() error = %v", err)
	}

	stream := YAMLStream(objects)
	for _, want := range []string{
		"kind: TracingPolicyNamespaced",
		"apiVersion: cilium.io/v1alpha1",
		"name: " + worker.Name + "-tracing",
		"__x64_sys_connect",
		"/usr/local/lib/node_modules/workerd/bin/workerd",
		"app.kubernetes.io/name: " + worker.Name,
	} {
		if !strings.Contains(stream, want) {
			t.Fatalf("rendered YAML missing %q\n%s", want, stream)
		}
	}
}

func TestRenderTracingPolicyResourceScopedToWorker(t *testing.T) {
	worker := sampleWorker()
	resources, err := RenderSandboxWorkerResources(worker, Options{HardeningProfile: tracingProfile()})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	if resources.TracingPolicy == nil {
		t.Fatal("TracingPolicy = nil, want a rendered policy")
	}
	policy := resources.TracingPolicy

	if gvk := policy.GroupVersionKind(); gvk != TracingPolicyGVK {
		t.Fatalf("GVK = %v, want %v", gvk, TracingPolicyGVK)
	}
	if got, want := policy.GetName(), TetragonPolicyName(worker); got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
	if got, want := policy.GetNamespace(), worker.Namespace; got != want {
		t.Fatalf("namespace = %q, want %q", got, want)
	}

	// The policy must select only this worker's pods, otherwise one worker's
	// tracing policy would trace (and be GC'd against) every workerd in the ns.
	selector, found, err := unstructuredNestedString(policy.Object, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name")
	if err != nil || !found {
		t.Fatalf("podSelector app name lookup: found=%v err=%v", found, err)
	}
	if selector != worker.Name {
		t.Fatalf("podSelector app name = %q, want %q", selector, worker.Name)
	}
}

func TestRenderTracingPolicyAbsentByDefault(t *testing.T) {
	// naked worker, no profile override -> no tetragon policy at all.
	resources, err := RenderSandboxWorkerResources(sampleWorker(), Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	if resources.TracingPolicy != nil {
		t.Fatalf("TracingPolicy = %v, want nil when profile sets no tetragonPolicyRef", resources.TracingPolicy)
	}
}

func TestRenderUnknownTetragonPolicyRefErrors(t *testing.T) {
	profile := &wulfv1alpha1.HardeningProfileSpec{TetragonPolicyRef: "bogus-policy"}

	if _, err := RenderSandboxWorker(sampleWorker(), Options{HardeningProfile: profile}); err == nil ||
		!strings.Contains(err.Error(), `unsupported tetragonPolicyRef "bogus-policy"`) {
		t.Fatalf("RenderSandboxWorker() error = %v, want unsupported tetragonPolicyRef", err)
	}
	if _, err := RenderSandboxWorkerResources(sampleWorker(), Options{HardeningProfile: profile}); err == nil ||
		!strings.Contains(err.Error(), `unsupported tetragonPolicyRef "bogus-policy"`) {
		t.Fatalf("RenderSandboxWorkerResources() error = %v, want unsupported tetragonPolicyRef", err)
	}
}

func unstructuredNestedString(obj map[string]interface{}, fields ...string) (string, bool, error) {
	cur := interface{}(obj)
	for _, field := range fields {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", false, nil
		}
		cur, ok = m[field]
		if !ok {
			return "", false, nil
		}
	}
	s, ok := cur.(string)
	return s, ok, nil
}
