package controller

import (
	"context"
	"reflect"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-local/operator/api/v1alpha1"
	"github.com/jlgore/workerwulf/wulf-local/operator/internal/render"
)

const FieldOwner = "wulf-local-operator"

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

	resources, err := render.RenderSandboxWorkerResources(worker, render.Options{Image: r.Image})
	if err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, &worker, statusForRenderError(worker, err))
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
		if err := ctrl.SetControllerReference(&worker, resources.Service, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Patch(ctx, resources.Service, client.Apply, client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
			return ctrl.Result{}, err
		}
	}

	status, err := r.observedStatus(ctx, &worker)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.updateStatus(ctx, &worker, status); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *SandboxWorkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wulfv1alpha1.SandboxWorker{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Complete(r)
}

func (r *SandboxWorkerReconciler) observedStatus(ctx context.Context, worker *wulfv1alpha1.SandboxWorker) (wulfv1alpha1.SandboxWorkerStatus, error) {
	status := wulfv1alpha1.SandboxWorkerStatus{
		Phase:                  "Pending",
		LastObservedGeneration: worker.Generation,
		HardeningApplied:       hardeningApplied(worker.Spec.Hardening.Profile),
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

func statusForRenderError(worker wulfv1alpha1.SandboxWorker, err error) wulfv1alpha1.SandboxWorkerStatus {
	status := wulfv1alpha1.SandboxWorkerStatus{
		Phase:                  "Failed",
		LastObservedGeneration: worker.Generation,
		HardeningApplied:       hardeningApplied(worker.Spec.Hardening.Profile),
	}
	setReadyCondition(&status, metav1.ConditionFalse, "RenderFailed", err.Error())
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

func hardeningApplied(profile string) wulfv1alpha1.HardeningApplied {
	if profile == "" {
		profile = "naked"
	}
	applied := wulfv1alpha1.HardeningApplied{Profile: profile}
	switch profile {
	case "seccomp-baseline", "seccomp-strict", "bpf-lsm", "full-lockdown":
		applied.SeccompProfile = "RuntimeDefault"
		applied.CapabilitiesDrop = []string{"ALL"}
		applied.RunAsNonRoot = true
	default:
		applied.SeccompProfile = "none"
	}
	return applied
}

func NamespacedName(worker *wulfv1alpha1.SandboxWorker) types.NamespacedName {
	return types.NamespacedName{Name: worker.Name, Namespace: worker.Namespace}
}
