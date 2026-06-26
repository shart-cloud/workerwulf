package render

import (
	"strings"
	"testing"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-operator/operator/api/v1alpha1"
)

func TestRenderSingleIsolateUnchanged(t *testing.T) {
	// maxIsolates unset (0) must render exactly the historical single-isolate
	// shape so existing workers are byte-stable.
	stream := MustRenderSandboxWorker(sampleWorker(), Options{})
	for _, want := range []string{
		`(name = "main", worker = .mainWorker)`,
		`address = "*:8080"`,
		"containerPort: 8080",
	} {
		if !strings.Contains(stream, want) {
			t.Fatalf("single-isolate render missing %q\n%s", want, stream)
		}
	}
	if strings.Contains(stream, "isolate-0") {
		t.Fatalf("single-isolate render should not mention isolate-0\n%s", stream)
	}
}

func TestRenderMultipleIsolates(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Runtime.MaxIsolates = 3
	stream := MustRenderSandboxWorker(worker, Options{})

	for _, want := range []string{
		// three co-located services, all sharing the one worker module...
		`(name = "isolate-0", worker = .mainWorker)`,
		`(name = "isolate-1", worker = .mainWorker)`,
		`(name = "isolate-2", worker = .mainWorker)`,
		// ...on three sockets/ports in the one process...
		`address = "*:8080"`,
		`address = "*:8081"`,
		`address = "*:8082"`,
		// ...exposed as three container ports and three service ports.
		"containerPort: 8080",
		"containerPort: 8081",
		"containerPort: 8082",
		"name: iso-1",
		"name: iso-2",
	} {
		if !strings.Contains(stream, want) {
			t.Fatalf("3-isolate render missing %q\n%s", want, stream)
		}
	}
}

func TestRenderMultipleIsolatesTypedResources(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Runtime.MaxIsolates = 2
	resources, err := RenderSandboxWorkerResources(worker, Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	if got := len(resources.Deployment.Spec.Template.Spec.Containers[0].Ports); got != 2 {
		t.Fatalf("container ports = %d, want 2", got)
	}
	if got := len(resources.Service.Spec.Ports); got != 2 {
		t.Fatalf("service ports = %d, want 2", got)
	}
	// Primary isolate keeps the named "http" port so the TCP probes keep working.
	if resources.Deployment.Spec.Template.Spec.Containers[0].Ports[0].Name != "http" {
		t.Fatalf("first container port name = %q, want http", resources.Deployment.Spec.Template.Spec.Containers[0].Ports[0].Name)
	}
}

func TestRenderMaxIsolatesOverLimitErrors(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Runtime.MaxIsolates = maxIsolatesLimit + 1
	if _, err := RenderSandboxWorkerResources(worker, Options{}); err == nil ||
		!strings.Contains(err.Error(), "exceeds the limit") {
		t.Fatalf("RenderSandboxWorkerResources() error = %v, want over-limit error", err)
	}
}

var _ = wulfv1alpha1.SandboxWorker{}
