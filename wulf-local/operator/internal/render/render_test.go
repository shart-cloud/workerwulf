package render

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-local/operator/api/v1alpha1"
)

func TestRenderSandboxWorkerInlineScript(t *testing.T) {
	worker := sampleWorker()
	objects, err := RenderSandboxWorker(worker, Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorker() error = %v", err)
	}

	if got, want := len(objects), 3; got != want {
		t.Fatalf("object count = %d, want %d", got, want)
	}

	stream := YAMLStream(objects)
	for _, want := range []string{
		"kind: ConfigMap",
		"kind: Deployment",
		"kind: Service",
		"esModule = embed \"../script/worker.js\"",
		"compatibilityDate = \"2024-09-23\"",
		"wulf.jaredgore.com/probe-id: P-WL-RT-001",
		"image: ghcr.io/jlgore/wulf-local-workerd:0.1.0",
		"          ports:",
	} {
		if !strings.Contains(stream, want) {
			t.Fatalf("rendered YAML missing %q\n%s", want, stream)
		}
	}
}

func TestRenderSandboxWorkerSeccompBaselineSecurityContext(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Hardening.Profile = "seccomp-baseline"

	objects, err := RenderSandboxWorker(worker, Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorker() error = %v", err)
	}

	stream := YAMLStream(objects)
	for _, want := range []string{
		"allowPrivilegeEscalation: false",
		"runAsNonRoot: true",
		"type: RuntimeDefault",
	} {
		if !strings.Contains(stream, want) {
			t.Fatalf("rendered YAML missing security setting %q\n%s", want, stream)
		}
	}
}

func TestRenderSandboxWorkerResourcesSeccompBaselineSecurityContext(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Hardening.Profile = "seccomp-baseline"

	resources, err := RenderSandboxWorkerResources(worker, Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}

	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	if container.SecurityContext == nil {
		t.Fatal("securityContext = nil")
	}
	if container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("allowPrivilegeEscalation = %v, want false", container.SecurityContext.AllowPrivilegeEscalation)
	}
	if container.SecurityContext.SeccompProfile == nil || container.SecurityContext.SeccompProfile.Type != "RuntimeDefault" {
		t.Fatalf("seccompProfile = %#v, want RuntimeDefault", container.SecurityContext.SeccompProfile)
	}
	if got := container.SecurityContext.Capabilities.Drop[0]; got != "ALL" {
		t.Fatalf("capabilities.drop[0] = %q, want ALL", got)
	}
}

func TestRenderSandboxWorkerResourcesResolvedSeccompBaselineProfile(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Hardening.Profile = "seccomp-baseline"
	allowPrivilegeEscalation := false
	profile := wulfv1alpha1.HardeningProfileSpec{
		Seccomp:                  wulfv1alpha1.SeccompSpec{Type: "RuntimeDefault"},
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		CapabilitiesDrop:         []corev1.Capability{corev1.Capability("ALL")},
		ReadOnlyRootFilesystem:   true,
		RunAsNonRoot:             true,
		RunAsUser:                65532,
	}

	resources, err := RenderSandboxWorkerResources(worker, Options{HardeningProfile: &profile})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}

	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	if container.SecurityContext == nil {
		t.Fatal("securityContext = nil")
	}
	if container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("allowPrivilegeEscalation = %v, want false", container.SecurityContext.AllowPrivilegeEscalation)
	}
	if container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatalf("readOnlyRootFilesystem = %v, want true", container.SecurityContext.ReadOnlyRootFilesystem)
	}
	if container.SecurityContext.RunAsNonRoot == nil || !*container.SecurityContext.RunAsNonRoot {
		t.Fatalf("runAsNonRoot = %v, want true", container.SecurityContext.RunAsNonRoot)
	}
	if container.SecurityContext.SeccompProfile == nil || container.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("seccompProfile = %#v, want RuntimeDefault", container.SecurityContext.SeccompProfile)
	}
	if got := container.SecurityContext.Capabilities.Drop[0]; got != "ALL" {
		t.Fatalf("capabilities.drop[0] = %q, want ALL", got)
	}
}

func TestRenderSandboxWorkerResourcesResolvedNakedProfile(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Hardening.Profile = "naked"
	profile := wulfv1alpha1.HardeningProfileSpec{
		Seccomp:                wulfv1alpha1.SeccompSpec{Type: "Unconfined"},
		ReadOnlyRootFilesystem: false,
		RunAsNonRoot:           false,
	}

	resources, err := RenderSandboxWorkerResources(worker, Options{HardeningProfile: &profile})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}

	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	if container.SecurityContext != nil {
		t.Fatalf("securityContext = %#v, want nil for naked baseline", container.SecurityContext)
	}
}

func TestRenderSandboxWorkerRejectsNonInlineScriptForNow(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Script.Inline = ""
	worker.Spec.Script.ConfigMapRef = &wulfv1alpha1.KeyRef{Name: "script", Key: "worker.js"}

	_, err := RenderSandboxWorker(worker, Options{})
	if err == nil {
		t.Fatal("RenderSandboxWorker() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "only spec.script.inline") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func sampleWorker() wulfv1alpha1.SandboxWorker {
	worker := wulfv1alpha1.NewSandboxWorker("workerd-rt-001", "wulf-system")
	worker.Labels = map[string]string{
		"wulf.jaredgore.com/track":    "runtime-fingerprint",
		"wulf.jaredgore.com/probe-id": "P-WL-RT-001",
	}
	worker.Spec = wulfv1alpha1.SandboxWorkerSpec{
		Script: wulfv1alpha1.ScriptSource{
			Inline: `export default { fetch() { return Response.json({ ok: true }); } };`,
		},
		CompatibilityDate:  "2024-09-23",
		CompatibilityFlags: []string{"nodejs_compat"},
		Bindings: wulfv1alpha1.WorkerBindings{
			Vars: map[string]string{
				"WORKER_NAME":       "workerd-rt-001",
				"HARDENING_PROFILE": "naked",
			},
		},
		Hardening: wulfv1alpha1.SandboxHardening{Profile: "naked"},
		Runtime: wulfv1alpha1.RuntimeSpec{
			Resources: wulfv1alpha1.ResourceSpec{
				Requests: wulfv1alpha1.ResourceList{CPU: "100m", Memory: "128Mi"},
				Limits:   wulfv1alpha1.ResourceList{CPU: "500m", Memory: "256Mi"},
			},
		},
		Exposure: wulfv1alpha1.ExposureSpec{Type: "ClusterIP", Port: 8080},
	}
	return worker
}
