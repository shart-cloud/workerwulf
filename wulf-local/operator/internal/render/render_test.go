package render

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

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
	if resources.NetworkPolicy != nil {
		t.Fatalf("networkPolicy = %#v, want nil for naked baseline", resources.NetworkPolicy)
	}
}

func TestRenderSandboxWorkerResourcesNoNetworkPolicyWithoutRef(t *testing.T) {
	worker := sampleWorker()
	profile := wulfv1alpha1.HardeningProfileSpec{
		Seccomp: wulfv1alpha1.SeccompSpec{Type: "Unconfined"},
	}

	resources, err := RenderSandboxWorkerResources(worker, Options{HardeningProfile: &profile})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	if resources.NetworkPolicy != nil {
		t.Fatalf("networkPolicy = %#v, want nil", resources.NetworkPolicy)
	}
}

func TestRenderSandboxWorkerResourcesDenyAllEgressNetworkPolicy(t *testing.T) {
	worker := sampleWorker()
	profile := wulfv1alpha1.HardeningProfileSpec{
		NetworkPolicyRef: NetworkPolicyDenyAllEgress,
	}

	resources, err := RenderSandboxWorkerResources(worker, Options{HardeningProfile: &profile})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	policy := resources.NetworkPolicy
	if policy == nil {
		t.Fatal("networkPolicy = nil")
	}
	if policy.Name != "workerd-rt-001-network-policy" {
		t.Fatalf("networkPolicy.name = %q, want workerd-rt-001-network-policy", policy.Name)
	}
	if got := policy.Spec.PodSelector.MatchLabels["app.kubernetes.io/name"]; got != worker.Name {
		t.Fatalf("podSelector app name = %q, want %q", got, worker.Name)
	}
	if len(policy.Spec.PolicyTypes) != 1 || policy.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("policyTypes = %#v, want [Egress]", policy.Spec.PolicyTypes)
	}
	if len(policy.Spec.Egress) != 0 {
		t.Fatalf("egress rules = %#v, want none for deny-all egress", policy.Spec.Egress)
	}
}

func TestRenderSandboxWorkerDenyAllEgressNetworkPolicyYAML(t *testing.T) {
	worker := sampleWorker()
	profile := wulfv1alpha1.HardeningProfileSpec{
		NetworkPolicyRef: NetworkPolicyDenyAllEgress,
	}

	objects, err := RenderSandboxWorker(worker, Options{HardeningProfile: &profile})
	if err != nil {
		t.Fatalf("RenderSandboxWorker() error = %v", err)
	}
	if got, want := len(objects), 4; got != want {
		t.Fatalf("object count = %d, want %d", got, want)
	}
	stream := YAMLStream(objects)
	for _, want := range []string{
		"kind: NetworkPolicy",
		"name: workerd-rt-001-network-policy",
		"app.kubernetes.io/name: workerd-rt-001",
		"- Egress",
		"egress: []",
	} {
		if !strings.Contains(stream, want) {
			t.Fatalf("rendered YAML missing network policy setting %q\n%s", want, stream)
		}
	}
}

func TestRenderSandboxWorkerRejectsUnknownNetworkPolicyRef(t *testing.T) {
	worker := sampleWorker()
	profile := wulfv1alpha1.HardeningProfileSpec{
		NetworkPolicyRef: "public-egress",
	}

	_, err := RenderSandboxWorkerResources(worker, Options{HardeningProfile: &profile})
	if err == nil {
		t.Fatal("RenderSandboxWorkerResources() error = nil, want error")
	}
	if !strings.Contains(err.Error(), `unsupported networkPolicyRef "public-egress"`) {
		t.Fatalf("unexpected error: %v", err)
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

func TestRenderSandboxWorkerResourcesDeniesServiceAccountToken(t *testing.T) {
	resources, err := RenderSandboxWorkerResources(sampleWorker(), Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	got := resources.Deployment.Spec.Template.Spec.AutomountServiceAccountToken
	if got == nil || *got {
		t.Fatalf("automountServiceAccountToken = %v, want false", got)
	}
}

func TestRenderSandboxWorkerResourcesTCPProbes(t *testing.T) {
	resources, err := RenderSandboxWorkerResources(sampleWorker(), Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	for name, probe := range map[string]*corev1.Probe{"readiness": container.ReadinessProbe, "liveness": container.LivenessProbe} {
		if probe == nil {
			t.Fatalf("%s probe = nil, want tcpSocket probe", name)
		}
		if probe.TCPSocket == nil {
			t.Fatalf("%s probe is not tcpSocket (httpGet would pollute probe results): %#v", name, probe.ProbeHandler)
		}
		if probe.HTTPGet != nil {
			t.Fatalf("%s probe uses httpGet; must be tcpSocket so it does not invoke the worker's fetch handler", name)
		}
	}
}

func TestRenderSandboxWorkerResourcesRejectsUnimplementedSpec(t *testing.T) {
	cases := map[string]func(*wulfv1alpha1.SandboxWorker){
		"maxIsolates":      func(w *wulfv1alpha1.SandboxWorker) { w.Spec.Runtime.MaxIsolates = 4 },
		"requestTimeoutMs": func(w *wulfv1alpha1.SandboxWorker) { w.Spec.Runtime.RequestTimeoutMs = 1000 },
		"coLocateWith":     func(w *wulfv1alpha1.SandboxWorker) { w.Spec.Runtime.CoLocateWith = "other" },
		"tracingPolicy":    func(w *wulfv1alpha1.SandboxWorker) { w.Spec.Instrumentation.TracingPolicy = "syscalls" },
		"git": func(w *wulfv1alpha1.SandboxWorker) {
			w.Spec.Script.Git = &wulfv1alpha1.GitScriptRef{Repo: "r", Path: "p"}
		},
	}
	for name, mutate := range cases {
		worker := sampleWorker()
		mutate(&worker)
		if _, err := RenderSandboxWorkerResources(worker, Options{}); err == nil {
			t.Fatalf("%s: expected error for unimplemented field, got nil", name)
		}
	}
}

func TestRenderSandboxWorkerResourcesV8Inspector(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Runtime.V8Inspector = true

	resources, err := RenderSandboxWorkerResources(worker, Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}

	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	wantArg := fmt.Sprintf("--inspector-addr=0.0.0.0:%d", DefaultInspectorPort)
	if !containsString(container.Args, wantArg) {
		t.Fatalf("container args = %v, want to contain %q", container.Args, wantArg)
	}
	if !hasPortNamed(container.Ports, "inspector") {
		t.Fatalf("container ports = %#v, want an 'inspector' port", container.Ports)
	}
	if resources.Service == nil || !hasServicePortNamed(resources.Service.Spec.Ports, "inspector") {
		t.Fatalf("service ports = %#v, want an 'inspector' port", resources.Service)
	}
}

func TestRenderSandboxWorkerResourcesNoInspectorByDefault(t *testing.T) {
	resources, err := RenderSandboxWorkerResources(sampleWorker(), Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	container := resources.Deployment.Spec.Template.Spec.Containers[0]
	if hasPortNamed(container.Ports, "inspector") {
		t.Fatal("inspector port present without spec.runtime.v8Inspector")
	}
	for _, arg := range container.Args {
		if strings.HasPrefix(arg, "--inspector-addr") {
			t.Fatalf("inspector arg %q present without spec.runtime.v8Inspector", arg)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func hasPortNamed(ports []corev1.ContainerPort, name string) bool {
	for _, p := range ports {
		if p.Name == name {
			return true
		}
	}
	return false
}

func hasServicePortNamed(ports []corev1.ServicePort, name string) bool {
	for _, p := range ports {
		if p.Name == name {
			return true
		}
	}
	return false
}

func TestRenderSandboxWorkerResultSinkEndpointBinding(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Instrumentation.ResultSink = wulfv1alpha1.ResultSink{Type: "http", Endpoint: "http://sink.wulf-system.svc/ingest"}

	objects, err := RenderSandboxWorker(worker, Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorker() error = %v", err)
	}
	if !strings.Contains(YAMLStream(objects), `name = "RESULT_SINK_URL", text = "http://sink.wulf-system.svc/ingest"`) {
		t.Fatalf("RESULT_SINK_URL not wired from resultSink.endpoint\n%s", YAMLStream(objects))
	}
}

func TestRenderSandboxWorkerPhantomProfileGivesNoFakeHardening(t *testing.T) {
	worker := sampleWorker()
	worker.Spec.Hardening.Profile = "bpf-lsm"

	resources, err := RenderSandboxWorkerResources(worker, Options{})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	if sc := resources.Deployment.Spec.Template.Spec.Containers[0].SecurityContext; sc != nil {
		t.Fatalf("phantom profile %q fabricated a securityContext = %#v; unimplemented profiles must not render fake hardening", worker.Spec.Hardening.Profile, sc)
	}
}

func TestRenderSandboxWorkerResourcesWritableTmpForReadOnlyRoot(t *testing.T) {
	worker := sampleWorker()
	profile := wulfv1alpha1.HardeningProfileSpec{
		Seccomp:                wulfv1alpha1.SeccompSpec{Type: "RuntimeDefault"},
		ReadOnlyRootFilesystem: true,
	}

	resources, err := RenderSandboxWorkerResources(worker, Options{HardeningProfile: &profile})
	if err != nil {
		t.Fatalf("RenderSandboxWorkerResources() error = %v", err)
	}
	pod := resources.Deployment.Spec.Template.Spec

	var tmpVol *corev1.Volume
	for i := range pod.Volumes {
		if pod.Volumes[i].Name == "tmp" {
			tmpVol = &pod.Volumes[i]
		}
	}
	if tmpVol == nil || tmpVol.EmptyDir == nil {
		t.Fatalf("expected an emptyDir 'tmp' volume so readOnlyRootFilesystem leaves writable scratch; volumes = %#v", pod.Volumes)
	}

	var mounted bool
	for _, m := range pod.Containers[0].VolumeMounts {
		if m.Name == "tmp" && m.MountPath == "/tmp" && !m.ReadOnly {
			mounted = true
		}
	}
	if !mounted {
		t.Fatalf("expected writable /tmp mount; mounts = %#v", pod.Containers[0].VolumeMounts)
	}
	if ro := pod.Containers[0].SecurityContext.ReadOnlyRootFilesystem; ro == nil || !*ro {
		t.Fatalf("readOnlyRootFilesystem = %v, want true", ro)
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
