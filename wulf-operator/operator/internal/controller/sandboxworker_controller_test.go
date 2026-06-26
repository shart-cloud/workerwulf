package controller

import (
	"context"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-operator/operator/api/v1alpha1"
	"github.com/jlgore/workerwulf/wulf-operator/operator/internal/render"
)

func TestReconcileMissingHardeningProfileSetsFailedStatus(t *testing.T) {
	worker := testWorker("missing-profile")
	worker.Spec.Hardening.Profile = "missing-profile"
	reconciler := newTestReconciler(t, &worker)

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

func TestHardeningProfileUpdateChangesRenderedDeploymentSecurityContext(t *testing.T) {
	ctx := context.Background()
	worker := testWorker("profile-update-worker")
	worker.Spec.Hardening.Profile = "seccomp-baseline"
	profile := testHardeningProfile("seccomp-baseline", worker.Namespace, testSeccompBaselineSpec())
	reconciler := newTestReconciler(t, &worker, &profile)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: NamespacedName(&worker)}); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}

	var deployment appsv1.Deployment
	if err := reconciler.Get(ctx, client.ObjectKey{Name: worker.Name, Namespace: worker.Namespace}, &deployment); err != nil {
		t.Fatalf("Get(Deployment) error = %v", err)
	}
	container := deployment.Spec.Template.Spec.Containers[0]
	if container.SecurityContext == nil {
		t.Fatal("initial securityContext = nil")
	}
	if container.SecurityContext.ReadOnlyRootFilesystem != nil {
		t.Fatalf("initial readOnlyRootFilesystem = %v, want nil", *container.SecurityContext.ReadOnlyRootFilesystem)
	}

	profile.Spec.ReadOnlyRootFilesystem = true
	if err := reconciler.Update(ctx, &profile); err != nil {
		t.Fatalf("Update(HardeningProfile) error = %v", err)
	}

	requests := reconciler.requestsForHardeningProfile(ctx, &profile)
	wantRequests := []ctrl.Request{{NamespacedName: NamespacedName(&worker)}}
	if !reflect.DeepEqual(requests, wantRequests) {
		t.Fatalf("requestsForHardeningProfile() = %#v, want %#v", requests, wantRequests)
	}
	for _, request := range requests {
		if _, err := reconciler.Reconcile(ctx, request); err != nil {
			t.Fatalf("Reconcile(%s) error = %v", request.NamespacedName, err)
		}
	}

	if err := reconciler.Get(ctx, client.ObjectKey{Name: worker.Name, Namespace: worker.Namespace}, &deployment); err != nil {
		t.Fatalf("Get(Deployment) after profile update error = %v", err)
	}
	container = deployment.Spec.Template.Spec.Containers[0]
	if container.SecurityContext == nil {
		t.Fatal("updated securityContext = nil")
	}
	if container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatalf("updated readOnlyRootFilesystem = %v, want true", container.SecurityContext.ReadOnlyRootFilesystem)
	}
}

func TestDeletingReferencedHardeningProfileMovesWorkerToFailed(t *testing.T) {
	ctx := context.Background()
	worker := testWorker("deleted-profile-worker")
	worker.Spec.Hardening.Profile = "seccomp-baseline"
	profile := testHardeningProfile("seccomp-baseline", worker.Namespace, testSeccompBaselineSpec())
	reconciler := newTestReconciler(t, &worker, &profile)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: NamespacedName(&worker)}); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	if err := reconciler.Delete(ctx, &profile); err != nil {
		t.Fatalf("Delete(HardeningProfile) error = %v", err)
	}

	requests := reconciler.requestsForHardeningProfile(ctx, &profile)
	wantRequests := []ctrl.Request{{NamespacedName: NamespacedName(&worker)}}
	if !reflect.DeepEqual(requests, wantRequests) {
		t.Fatalf("requestsForHardeningProfile() after delete = %#v, want %#v", requests, wantRequests)
	}
	for _, request := range requests {
		if _, err := reconciler.Reconcile(ctx, request); err != nil {
			t.Fatalf("Reconcile(%s) after profile delete error = %v", request.NamespacedName, err)
		}
	}

	var got wulfv1alpha1.SandboxWorker
	if err := reconciler.Get(ctx, NamespacedName(&worker), &got); err != nil {
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
}

func TestNetworkPolicyRefAppliesDenyAllEgressAndDeletesWhenRemoved(t *testing.T) {
	ctx := context.Background()
	worker := testWorker("network-policy-worker")
	worker.Spec.Hardening.Profile = "networked"
	profile := testHardeningProfile("networked", worker.Namespace, wulfv1alpha1.HardeningProfileSpec{
		NetworkPolicyRef: "deny-all-egress",
	})
	reconciler := newTestReconciler(t, &worker, &profile)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: NamespacedName(&worker)}); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}

	var policy networkingv1.NetworkPolicy
	policyKey := client.ObjectKey{Name: "network-policy-worker-network-policy", Namespace: worker.Namespace}
	if err := reconciler.Get(ctx, policyKey, &policy); err != nil {
		t.Fatalf("Get(NetworkPolicy) error = %v", err)
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

	profile.Spec.NetworkPolicyRef = ""
	if err := reconciler.Update(ctx, &profile); err != nil {
		t.Fatalf("Update(HardeningProfile) error = %v", err)
	}
	requests := reconciler.requestsForHardeningProfile(ctx, &profile)
	wantRequests := []ctrl.Request{{NamespacedName: NamespacedName(&worker)}}
	if !reflect.DeepEqual(requests, wantRequests) {
		t.Fatalf("requestsForHardeningProfile() = %#v, want %#v", requests, wantRequests)
	}
	for _, request := range requests {
		if _, err := reconciler.Reconcile(ctx, request); err != nil {
			t.Fatalf("Reconcile(%s) after removing networkPolicyRef error = %v", request.NamespacedName, err)
		}
	}

	err := reconciler.Get(ctx, policyKey, &policy)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Get(NetworkPolicy) after removing networkPolicyRef error = %v, want NotFound", err)
	}
}

func TestUnknownNetworkPolicyRefSetsFailedStatus(t *testing.T) {
	ctx := context.Background()
	worker := testWorker("unknown-network-policy-worker")
	worker.Spec.Hardening.Profile = "unknown-network-policy"
	profile := testHardeningProfile("unknown-network-policy", worker.Namespace, wulfv1alpha1.HardeningProfileSpec{
		NetworkPolicyRef: "public-egress",
	})
	reconciler := newTestReconciler(t, &worker, &profile)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: NamespacedName(&worker)}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	var got wulfv1alpha1.SandboxWorker
	if err := reconciler.Get(ctx, NamespacedName(&worker), &got); err != nil {
		t.Fatalf("Get(SandboxWorker) error = %v", err)
	}
	if got.Status.Phase != "Failed" {
		t.Fatalf("status.phase = %q, want Failed", got.Status.Phase)
	}
	condition := readyCondition(got.Status.Conditions)
	if condition == nil {
		t.Fatal("Ready condition missing")
	}
	if condition.Reason != "RenderFailed" {
		t.Fatalf("Ready reason = %q, want RenderFailed", condition.Reason)
	}
	if !strings.Contains(condition.Message, `unsupported networkPolicyRef "public-egress"`) {
		t.Fatalf("Ready message = %q, want unsupported networkPolicyRef detail", condition.Message)
	}
}

func TestTetragonPolicyRefAppliesTracingPolicyAndDeletesWhenRemoved(t *testing.T) {
	ctx := context.Background()
	worker := testWorker("traced-worker")
	worker.Spec.Hardening.Profile = "traced"
	profile := testHardeningProfile("traced", worker.Namespace, wulfv1alpha1.HardeningProfileSpec{
		Seccomp:           wulfv1alpha1.SeccompSpec{Type: "RuntimeDefault"},
		TetragonPolicyRef: render.TetragonPolicyWorkerdSyscalls,
	})
	reconciler := newTestReconciler(t, &worker, &profile)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: NamespacedName(&worker)}); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}

	policyKey := client.ObjectKey{Name: render.TetragonPolicyName(worker), Namespace: worker.Namespace}
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(render.TracingPolicyGVK)
	if err := reconciler.Get(ctx, policyKey, policy); err != nil {
		t.Fatalf("Get(TracingPolicyNamespaced) error = %v", err)
	}
	selector, found, err := unstructured.NestedString(policy.Object, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name")
	if err != nil || !found || selector != worker.Name {
		t.Fatalf("podSelector app name = %q (found=%v err=%v), want %q", selector, found, err, worker.Name)
	}

	// status must reflect the applied policy ref for the Examiner Portal.
	var got wulfv1alpha1.SandboxWorker
	if err := reconciler.Get(ctx, NamespacedName(&worker), &got); err != nil {
		t.Fatalf("Get(SandboxWorker) error = %v", err)
	}
	if got.Status.HardeningApplied.TetragonPolicy != render.TetragonPolicyWorkerdSyscalls {
		t.Fatalf("status.hardeningApplied.tetragonPolicy = %q, want %q", got.Status.HardeningApplied.TetragonPolicy, render.TetragonPolicyWorkerdSyscalls)
	}

	// Drop the ref: the operator must delete the now-orphaned policy.
	profile.Spec.TetragonPolicyRef = ""
	if err := reconciler.Update(ctx, &profile); err != nil {
		t.Fatalf("Update(HardeningProfile) error = %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: NamespacedName(&worker)}); err != nil {
		t.Fatalf("Reconcile() after removing tetragonPolicyRef error = %v", err)
	}
	if err := reconciler.Get(ctx, policyKey, policy); !apierrors.IsNotFound(err) {
		t.Fatalf("Get(TracingPolicyNamespaced) after removing ref error = %v, want NotFound", err)
	}
}

func TestUnknownTetragonPolicyRefSetsFailedStatus(t *testing.T) {
	ctx := context.Background()
	worker := testWorker("unknown-tetragon-worker")
	worker.Spec.Hardening.Profile = "unknown-tetragon"
	profile := testHardeningProfile("unknown-tetragon", worker.Namespace, wulfv1alpha1.HardeningProfileSpec{
		TetragonPolicyRef: "exfil-everything",
	})
	reconciler := newTestReconciler(t, &worker, &profile)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: NamespacedName(&worker)}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	var got wulfv1alpha1.SandboxWorker
	if err := reconciler.Get(ctx, NamespacedName(&worker), &got); err != nil {
		t.Fatalf("Get(SandboxWorker) error = %v", err)
	}
	if got.Status.Phase != "Failed" {
		t.Fatalf("status.phase = %q, want Failed", got.Status.Phase)
	}
	condition := readyCondition(got.Status.Conditions)
	if condition == nil || condition.Reason != "RenderFailed" {
		t.Fatalf("Ready condition = %#v, want RenderFailed", condition)
	}
	if !strings.Contains(condition.Message, `unsupported tetragonPolicyRef "exfil-everything"`) {
		t.Fatalf("Ready message = %q, want unsupported tetragonPolicyRef detail", condition.Message)
	}
}

func TestUnrelatedHardeningProfileChangeDoesNotEnqueueWorkers(t *testing.T) {
	worker := testWorker("seccomp-worker")
	worker.Spec.Hardening.Profile = "seccomp-baseline"
	profile := testHardeningProfile("unrelated", worker.Namespace, testSeccompBaselineSpec())
	reconciler := newTestReconciler(t, &worker, &profile)

	requests := reconciler.requestsForHardeningProfile(context.Background(), &profile)
	if len(requests) != 0 {
		t.Fatalf("requestsForHardeningProfile() = %#v, want none", requests)
	}
}

func TestResolveHardeningProfileUsesSandboxWorkerNamespace(t *testing.T) {
	worker := testWorker("seccomp-worker")
	worker.Spec.Hardening.Profile = "seccomp-baseline"
	profile := testHardeningProfile("seccomp-baseline", worker.Namespace, testSeccompBaselineSpec())
	reconciler := newTestReconciler(t, &worker, &profile)

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

func newTestReconciler(t *testing.T, objects ...client.Object) *SandboxWorkerReconciler {
	t.Helper()
	scheme := testScheme(t)
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&wulfv1alpha1.SandboxWorker{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
				// The fake client does not implement server-side apply for these
				// kinds, so emulate create-or-update for the objects the
				// reconciler applies that way (NetworkPolicy and the unstructured
				// Tetragon TracingPolicyNamespaced).
				if patch != client.Apply {
					return c.Patch(ctx, object, patch, opts...)
				}
				switch object.(type) {
				case *networkingv1.NetworkPolicy:
				case *unstructured.Unstructured:
				default:
					return c.Patch(ctx, object, patch, opts...)
				}
				current := object.DeepCopyObject().(client.Object)
				key := client.ObjectKeyFromObject(object)
				if err := c.Get(ctx, key, current); err != nil {
					if apierrors.IsNotFound(err) {
						return c.Create(ctx, object)
					}
					return err
				}
				object.SetResourceVersion(current.GetResourceVersion())
				return c.Update(ctx, object)
			},
		}).
		WithIndex(
			&wulfv1alpha1.SandboxWorker{},
			sandboxWorkerHardeningProfileField,
			sandboxWorkerHardeningProfileIndex,
		)
	if len(objects) > 0 {
		builder.WithObjects(objects...)
	}
	return &SandboxWorkerReconciler{
		Client: builder.Build(),
		Scheme: scheme,
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
	if err := networkingv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(networkingv1) error = %v", err)
	}
	if err := wulfv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(wulf) error = %v", err)
	}
	// Tetragon's TracingPolicyNamespaced has no Go type in our deps; register it
	// as unstructured so the fake client tracker can store what the controller
	// server-side applies.
	scheme.AddKnownTypeWithName(render.TracingPolicyGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(
		render.TracingPolicyGVK.GroupVersion().WithKind(render.TracingPolicyGVK.Kind+"List"),
		&unstructured.UnstructuredList{},
	)
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
