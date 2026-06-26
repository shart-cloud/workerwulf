package controller

import (
	"context"
	"fmt"
	"reflect"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-operator/operator/api/v1alpha1"
	"github.com/jlgore/workerwulf/wulf-operator/operator/internal/render"
)

const FieldOwner = "wulf-operator"
const sandboxWorkerHardeningProfileField = "spec.hardening.profile"

type SandboxWorkerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Image  string
}

func (r *SandboxWorkerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var worker wulfv1alpha1.SandboxWorker
	if err := r.Get(ctx, req.NamespacedName, &worker); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	profile, err := r.resolveHardeningProfile(ctx, &worker)
	if err != nil {
		status := statusForProfileError(worker, hardeningProfileName(&worker), err)
		if updateErr := r.updateStatus(ctx, &worker, status); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	resources, err := render.RenderSandboxWorkerResources(worker, render.Options{Image: r.Image, HardeningProfile: &profile.Spec})
	if err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &worker, statusForRenderError(worker, &profile.Spec, err))
	}

	for _, object := range []client.Object{resources.ConfigMap, resources.Deployment} {
		if err := ctrl.SetControllerReference(&worker, object, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Patch(ctx, object, client.Apply, client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
			return ctrl.Result{}, err
		}
	}

	if resources.Service != nil {
		if err := r.applyOwned(ctx, &worker, resources.Service); err != nil {
			return ctrl.Result{}, err
		}
	}

	if resources.NetworkPolicy != nil {
		if err := r.applyOwned(ctx, &worker, resources.NetworkPolicy); err != nil {
			return ctrl.Result{}, err
		}
	} else if err := r.deleteNetworkPolicy(ctx, &worker); err != nil {
		return ctrl.Result{}, err
	}

	if resources.TracingPolicy != nil {
		if err := r.applyOwned(ctx, &worker, resources.TracingPolicy); err != nil {
			return ctrl.Result{}, err
		}
	} else if err := r.deleteTracingPolicy(ctx, &worker); err != nil {
		return ctrl.Result{}, err
	}

	status, err := r.observedStatus(ctx, &worker, &profile.Spec)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.updateStatus(ctx, &worker, status); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *SandboxWorkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&wulfv1alpha1.SandboxWorker{},
		sandboxWorkerHardeningProfileField,
		sandboxWorkerHardeningProfileIndex,
	); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&wulfv1alpha1.SandboxWorker{}).
		Watches(
			&wulfv1alpha1.HardeningProfile{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForHardeningProfile),
		).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Complete(r)
}

func (r *SandboxWorkerReconciler) applyOwned(ctx context.Context, worker *wulfv1alpha1.SandboxWorker, object client.Object) error {
	if err := ctrl.SetControllerReference(worker, object, r.Scheme); err != nil {
		return err
	}
	return r.Patch(ctx, object, client.Apply, client.FieldOwner(FieldOwner), client.ForceOwnership)
}

func (r *SandboxWorkerReconciler) deleteNetworkPolicy(ctx context.Context, worker *wulfv1alpha1.SandboxWorker) error {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.NetworkPolicyName(*worker),
			Namespace: hardeningProfileNamespace(worker),
		},
	}
	return client.IgnoreNotFound(r.Delete(ctx, policy))
}

func (r *SandboxWorkerReconciler) deleteTracingPolicy(ctx context.Context, worker *wulfv1alpha1.SandboxWorker) error {
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(render.TracingPolicyGVK)
	policy.SetName(render.TetragonPolicyName(*worker))
	policy.SetNamespace(worker.Namespace)
	// A worker whose profile never set tetragonPolicyRef has no policy and,
	// on a cluster without the Tetragon CRDs, the kind itself is unknown.
	// Treat both NotFound and "no matching kind" as already-absent so the
	// common naked/seccomp path never wedges the reconcile.
	err := r.Delete(ctx, policy)
	if apimeta.IsNoMatchError(err) {
		return nil
	}
	return client.IgnoreNotFound(err)
}

func (r *SandboxWorkerReconciler) requestsForHardeningProfile(ctx context.Context, object client.Object) []ctrl.Request {
	if object == nil || object.GetName() == "" {
		return nil
	}

	var workers wulfv1alpha1.SandboxWorkerList
	if err := r.List(ctx, &workers,
		client.InNamespace(object.GetNamespace()),
		client.MatchingFields{sandboxWorkerHardeningProfileField: object.GetName()},
	); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "list SandboxWorkers for HardeningProfile", "profile", object.GetName(), "namespace", object.GetNamespace())
		return nil
	}

	requests := make([]ctrl.Request, 0, len(workers.Items))
	for i := range workers.Items {
		worker := &workers.Items[i]
		requests = append(requests, ctrl.Request{NamespacedName: NamespacedName(worker)})
	}
	return requests
}

func (r *SandboxWorkerReconciler) resolveHardeningProfile(ctx context.Context, worker *wulfv1alpha1.SandboxWorker) (*wulfv1alpha1.HardeningProfile, error) {
	var profile wulfv1alpha1.HardeningProfile
	err := r.Get(ctx, types.NamespacedName{
		Name:      hardeningProfileName(worker),
		Namespace: hardeningProfileNamespace(worker),
	}, &profile)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func (r *SandboxWorkerReconciler) observedStatus(ctx context.Context, worker *wulfv1alpha1.SandboxWorker, profile *wulfv1alpha1.HardeningProfileSpec) (wulfv1alpha1.SandboxWorkerStatus, error) {
	status := wulfv1alpha1.SandboxWorkerStatus{
		Phase:                  "Pending",
		LastObservedGeneration: worker.Generation,
		HardeningApplied:       hardeningApplied(hardeningProfileName(worker), profile),
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods,
		client.InNamespace(worker.Namespace),
		client.MatchingLabels{"app.kubernetes.io/name": worker.Name},
	); err != nil {
		return status, err
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		status.PodName = pod.Name
		status.PodIP = pod.Status.PodIP
		status.NodeName = pod.Spec.NodeName
		status.StartedAt = pod.Status.StartTime
		if podReady(pod) {
			status.Phase = "Running"
			setReadyCondition(&status, metav1.ConditionTrue, "PodReady", "At least one owned pod is ready")
			return status, nil
		}
	}

	if status.PodName != "" {
		setReadyCondition(&status, metav1.ConditionFalse, "PodNotReady", "Owned pod exists but is not ready")
	} else {
		setReadyCondition(&status, metav1.ConditionFalse, "PodMissing", "No owned pod has been observed yet")
	}
	return status, nil
}

func (r *SandboxWorkerReconciler) updateStatus(ctx context.Context, worker *wulfv1alpha1.SandboxWorker, status wulfv1alpha1.SandboxWorkerStatus) error {
	if reflect.DeepEqual(worker.Status, status) {
		return nil
	}
	patch := client.MergeFrom(worker.DeepCopy())
	worker.Status = status
	return r.Status().Patch(ctx, worker, patch)
}

func statusForRenderError(worker wulfv1alpha1.SandboxWorker, profile *wulfv1alpha1.HardeningProfileSpec, err error) wulfv1alpha1.SandboxWorkerStatus {
	status := wulfv1alpha1.SandboxWorkerStatus{
		Phase:                  "Failed",
		LastObservedGeneration: worker.Generation,
		HardeningApplied:       hardeningApplied(hardeningProfileName(&worker), profile),
	}
	setReadyCondition(&status, metav1.ConditionFalse, "RenderFailed", err.Error())
	return status
}

func statusForProfileError(worker wulfv1alpha1.SandboxWorker, profile string, err error) wulfv1alpha1.SandboxWorkerStatus {
	status := wulfv1alpha1.SandboxWorkerStatus{
		Phase:                  "Failed",
		LastObservedGeneration: worker.Generation,
		HardeningApplied:       hardeningApplied(profile, nil),
	}
	reason := "HardeningProfileResolveFailed"
	message := fmt.Sprintf("failed to resolve HardeningProfile %q in namespace %q: %v", profile, hardeningProfileNamespace(&worker), err)
	if apierrors.IsNotFound(err) {
		reason = "HardeningProfileNotFound"
		message = fmt.Sprintf("HardeningProfile %q was not found in namespace %q", profile, hardeningProfileNamespace(&worker))
	}
	setReadyCondition(&status, metav1.ConditionFalse, reason, message)
	return status
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func setReadyCondition(status *wulfv1alpha1.SandboxWorkerStatus, conditionStatus metav1.ConditionStatus, reason, message string) {
	apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             conditionStatus,
		ObservedGeneration: status.LastObservedGeneration,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})
}

func hardeningApplied(profile string, spec *wulfv1alpha1.HardeningProfileSpec) wulfv1alpha1.HardeningApplied {
	if profile == "" {
		profile = "naked"
	}
	applied := wulfv1alpha1.HardeningApplied{Profile: profile}
	if spec == nil {
		applied.SeccompProfile = "none"
		return applied
	}

	if spec.Seccomp.Type == "" || spec.Seccomp.Type == "Unconfined" {
		applied.SeccompProfile = "none"
	} else {
		applied.SeccompProfile = spec.Seccomp.Type
	}
	applied.CapabilitiesDrop = make([]string, 0, len(spec.CapabilitiesDrop))
	for _, capability := range spec.CapabilitiesDrop {
		applied.CapabilitiesDrop = append(applied.CapabilitiesDrop, string(capability))
	}
	applied.RunAsNonRoot = spec.RunAsNonRoot
	applied.ReadOnlyRootFS = spec.ReadOnlyRootFilesystem
	applied.NetworkPolicy = spec.NetworkPolicyRef
	applied.TetragonPolicy = spec.TetragonPolicyRef
	return applied
}

func hardeningProfileName(worker *wulfv1alpha1.SandboxWorker) string {
	if worker.Spec.Hardening.Profile == "" {
		return "naked"
	}
	return worker.Spec.Hardening.Profile
}

func sandboxWorkerHardeningProfileIndex(object client.Object) []string {
	worker, ok := object.(*wulfv1alpha1.SandboxWorker)
	if !ok {
		return nil
	}
	return []string{hardeningProfileName(worker)}
}

func hardeningProfileNamespace(worker *wulfv1alpha1.SandboxWorker) string {
	if worker.Namespace == "" {
		return "wulf-system"
	}
	return worker.Namespace
}

func NamespacedName(worker *wulfv1alpha1.SandboxWorker) types.NamespacedName {
	return types.NamespacedName{Name: worker.Name, Namespace: worker.Namespace}
}
