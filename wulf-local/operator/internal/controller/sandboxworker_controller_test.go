package controller

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-local/operator/api/v1alpha1"
)

func TestReconcileMissingHardeningProfileSetsFailedStatus(t *testing.T) {
	scheme := testScheme(t)
	worker := testWorker("missing-profile")
	worker.Spec.Hardening.Profile = "missing-profile"
	reconciler := &SandboxWorkerReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&wulfv1alpha1.SandboxWorker{}).
			WithObjects(&worker).
			Build(),
		Scheme: scheme,
	}

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: NamespacedName(&worker)})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	var got wulfv1alpha1.SandboxWorker
	if err := reconciler.Get(context.Background(), NamespacedName(&worker), &got); err != nil {
		t.Fatalf("Get(SandboxWorker) error = %v", err)
	}
	if got.Status.Phase != "Failed" {
		t.Fatalf("status.phase = %q, want Failed", got.Status.Phase)
	}
	condition := readyCondition(got.Status.Conditions)
	if condition == nil {
		t.Fatal("Ready condition missing")
	}
	if condition.Reason != "HardeningProfileNotFound" {
		t.Fatalf("Ready reason = %q, want HardeningProfileNotFound", condition.Reason)
	}
	if !strings.Contains(condition.Message, `HardeningProfile "missing-profile" was not found`) {
		t.Fatalf("Ready message = %q, want missing profile detail", condition.Message)
	}

	var deployment appsv1.Deployment
	err = reconciler.Get(context.Background(), client.ObjectKey{Name: worker.Name, Namespace: worker.Namespace}, &deployment)
	if err == nil {
		t.Fatal("Deployment exists, want no rendered resources when profile resolution fails")
	}
}

func TestResolveHardeningProfileUsesSandboxWorkerNamespace(t *testing.T) {
	scheme := testScheme(t)
	worker := testWorker("seccomp-worker")
	worker.Spec.Hardening.Profile = "seccomp-baseline"
	profile := testHardeningProfile("seccomp-baseline", worker.Namespace, testSeccompBaselineSpec())
	reconciler := &SandboxWorkerReconciler{
		Client: fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&worker, &profile).
			Build(),
		Scheme: scheme,
	}

	resolved, err := reconciler.resolveHardeningProfile(context.Background(), &worker)
	if err != nil {
		t.Fatalf("resolveHardeningProfile() error = %v", err)
	}
	if resolved.Name != "seccomp-baseline" || resolved.Namespace != worker.Namespace {
		t.Fatalf("resolved profile = %s/%s, want %s/%s", resolved.Namespace, resolved.Name, worker.Namespace, "seccomp-baseline")
	}
	if resolved.Spec.Seccomp.Type != "RuntimeDefault" {
		t.Fatalf("resolved seccomp type = %q, want RuntimeDefault", resolved.Spec.Seccomp.Type)
	}
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(client-go) error = %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(corev1) error = %v", err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(appsv1) error = %v", err)
	}
	if err := wulfv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(wulf) error = %v", err)
	}
	return scheme
}

func testWorker(name string) wulfv1alpha1.SandboxWorker {
	worker := wulfv1alpha1.NewSandboxWorker(name, "wulf-system")
	worker.Spec = wulfv1alpha1.SandboxWorkerSpec{
		Script: wulfv1alpha1.ScriptSource{
			Inline: `export default { fetch() { return Response.json({ ok: true }); } };`,
		},
		Hardening: wulfv1alpha1.SandboxHardening{Profile: "naked"},
		Exposure:  wulfv1alpha1.ExposureSpec{Type: "ClusterIP", Port: 8080},
	}
	return worker
}

func testHardeningProfile(name, namespace string, spec wulfv1alpha1.HardeningProfileSpec) wulfv1alpha1.HardeningProfile {
	return wulfv1alpha1.HardeningProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: wulfv1alpha1.SchemeGroupVersion.String(),
			Kind:       wulfv1alpha1.KindHardeningProfile,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: spec,
	}
}

func testSeccompBaselineSpec() wulfv1alpha1.HardeningProfileSpec {
	allowPrivilegeEscalation := false
	return wulfv1alpha1.HardeningProfileSpec{
		Seccomp:                  wulfv1alpha1.SeccompSpec{Type: "RuntimeDefault"},
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		CapabilitiesDrop:         []corev1.Capability{corev1.Capability("ALL")},
		RunAsNonRoot:             true,
		RunAsUser:                65532,
	}
}

func readyCondition(conditions []metav1.Condition) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == "Ready" {
			return &conditions[i]
		}
	}
	return nil
}
