package render

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-local/operator/api/v1alpha1"
)

type Resources struct {
	ConfigMap     *corev1.ConfigMap
	Deployment    *appsv1.Deployment
	Service       *corev1.Service
	NetworkPolicy *networkingv1.NetworkPolicy
}

func RenderSandboxWorkerResources(worker wulfv1alpha1.SandboxWorker, opts Options) (Resources, error) {
	normalized, err := normalize(worker, opts)
	if err != nil {
		return Resources{}, err
	}

	config, err := renderWorkerdConfig(normalized)
	if err != nil {
		return Resources{}, err
	}

	labels := copyLabels(normalized.Labels)
	configMap := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      normalized.ConfigMapName,
			Namespace: normalized.Namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			"workerd.capnp": config,
			"worker.js":     normalized.InlineScript,
		},
	}

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      normalized.Name,
			Namespace: normalized.Namespace,
			Labels:    copyLabels(labels),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/name": normalized.Name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: copyLabels(labels)},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "workerd",
							Image:           normalized.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								"serve",
								"/etc/workerd/config/workerd.capnp",
								"-I",
								"/usr/local/lib/node_modules/workerd",
							},
							Ports: []corev1.ContainerPort{
								{Name: "http", ContainerPort: 8080},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(normalized.CPURequest),
									corev1.ResourceMemory: resource.MustParse(normalized.MemoryRequest),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse(normalized.CPULimit),
									corev1.ResourceMemory: resource.MustParse(normalized.MemoryLimit),
								},
							},
							SecurityContext: securityContextResourceFor(normalized.HardeningProfile, normalized.HardeningSpec),
							VolumeMounts: []corev1.VolumeMount{
								{Name: "workerd-config", MountPath: "/etc/workerd", ReadOnly: true},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "workerd-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: normalized.ConfigMapName},
									Items: []corev1.KeyToPath{
										{Key: "workerd.capnp", Path: "config/workerd.capnp"},
										{Key: "worker.js", Path: "script/worker.js"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	var service *corev1.Service
	if normalized.ExposureType != "None" {
		service = &corev1.Service{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      normalized.Name,
				Namespace: normalized.Namespace,
				Labels:    copyLabels(labels),
			},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceType(normalized.ExposureType),
				Selector: map[string]string{"app.kubernetes.io/name": normalized.Name},
				Ports: []corev1.ServicePort{
					{Name: "http", Port: int32(normalized.Port), TargetPort: intstr.FromString("http")},
				},
			},
		}
	}

	networkPolicy := networkPolicyResourceFor(normalized, labels)

	return Resources{ConfigMap: configMap, Deployment: deployment, Service: service, NetworkPolicy: networkPolicy}, nil
}

func copyLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func int32Ptr(value int32) *int32 {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}

func NetworkPolicyName(worker wulfv1alpha1.SandboxWorker) string {
	return worker.Name + "-network-policy"
}

func networkPolicyResourceFor(worker normalizedWorker, labels map[string]string) *networkingv1.NetworkPolicy {
	switch worker.NetworkPolicyRef {
	case "":
		return nil
	case NetworkPolicyDenyAllEgress:
		return &networkingv1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      worker.NetworkPolicyName,
				Namespace: worker.Namespace,
				Labels:    copyLabels(labels),
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app.kubernetes.io/name": worker.Name},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}
	default:
		return nil
	}
}

func hardeningProfileSpecFor(profile string, resolved *wulfv1alpha1.HardeningProfileSpec) *wulfv1alpha1.HardeningProfileSpec {
	if resolved != nil {
		return resolved.DeepCopy()
	}
	switch profile {
	case "seccomp-baseline", "seccomp-strict", "bpf-lsm", "full-lockdown":
		allowPrivilegeEscalation := false
		return &wulfv1alpha1.HardeningProfileSpec{
			Seccomp:                  wulfv1alpha1.SeccompSpec{Type: string(corev1.SeccompProfileTypeRuntimeDefault)},
			AllowPrivilegeEscalation: &allowPrivilegeEscalation,
			CapabilitiesDrop:         []corev1.Capability{corev1.Capability("ALL")},
			RunAsNonRoot:             true,
			RunAsUser:                65532,
		}
	default:
		return nil
	}
}

func securityContextResourceFor(profile string, spec *wulfv1alpha1.HardeningProfileSpec) *corev1.SecurityContext {
	spec = hardeningProfileSpecFor(profile, spec)
	if spec == nil {
		return nil
	}

	securityContext := &corev1.SecurityContext{}
	hasSecurityContext := false

	if spec.AllowPrivilegeEscalation != nil {
		securityContext.AllowPrivilegeEscalation = boolPtr(*spec.AllowPrivilegeEscalation)
		hasSecurityContext = true
	}

	if len(spec.CapabilitiesDrop) > 0 || len(spec.CapabilitiesAdd) > 0 {
		securityContext.Capabilities = &corev1.Capabilities{
			Drop: append([]corev1.Capability(nil), spec.CapabilitiesDrop...),
			Add:  append([]corev1.Capability(nil), spec.CapabilitiesAdd...),
		}
		hasSecurityContext = true
	}

	if spec.ReadOnlyRootFilesystem {
		securityContext.ReadOnlyRootFilesystem = boolPtr(true)
		hasSecurityContext = true
	}

	if spec.RunAsNonRoot {
		securityContext.RunAsNonRoot = boolPtr(true)
		hasSecurityContext = true
	}

	if spec.RunAsUser != 0 {
		securityContext.RunAsUser = int64Ptr(spec.RunAsUser)
		hasSecurityContext = true
	}

	switch spec.Seccomp.Type {
	case string(corev1.SeccompProfileTypeRuntimeDefault):
		securityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		hasSecurityContext = true
	case string(corev1.SeccompProfileTypeLocalhost):
		securityContext.SeccompProfile = &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: stringPtr(spec.Seccomp.ProfileRef),
		}
		hasSecurityContext = true
	case "", string(corev1.SeccompProfileTypeUnconfined):
		// The naked baseline intentionally leaves the container security context unset.
	default:
		securityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileType(spec.Seccomp.Type)}
		hasSecurityContext = true
	}

	if !hasSecurityContext {
		return nil
	}
	return securityContext
}

func securityContextFor(profile string, spec *wulfv1alpha1.HardeningProfileSpec) string {
	securityContext := securityContextResourceFor(profile, spec)
	if securityContext == nil {
		return ""
	}

	var builder strings.Builder
	builder.WriteString("          securityContext:\n")
	if securityContext.AllowPrivilegeEscalation != nil {
		builder.WriteString(fmt.Sprintf("            allowPrivilegeEscalation: %t\n", *securityContext.AllowPrivilegeEscalation))
	}
	if securityContext.Capabilities != nil {
		builder.WriteString("            capabilities:\n")
		if len(securityContext.Capabilities.Add) > 0 {
			builder.WriteString("              add:\n")
			for _, capability := range securityContext.Capabilities.Add {
				builder.WriteString(fmt.Sprintf("                - %s\n", capability))
			}
		}
		if len(securityContext.Capabilities.Drop) > 0 {
			builder.WriteString("              drop:\n")
			for _, capability := range securityContext.Capabilities.Drop {
				builder.WriteString(fmt.Sprintf("                - %s\n", capability))
			}
		}
	}
	if securityContext.ReadOnlyRootFilesystem != nil {
		builder.WriteString(fmt.Sprintf("            readOnlyRootFilesystem: %t\n", *securityContext.ReadOnlyRootFilesystem))
	}
	if securityContext.RunAsNonRoot != nil {
		builder.WriteString(fmt.Sprintf("            runAsNonRoot: %t\n", *securityContext.RunAsNonRoot))
	}
	if securityContext.RunAsUser != nil {
		builder.WriteString(fmt.Sprintf("            runAsUser: %d\n", *securityContext.RunAsUser))
	}
	if securityContext.SeccompProfile != nil {
		builder.WriteString("            seccompProfile:\n")
		builder.WriteString(fmt.Sprintf("              type: %s\n", securityContext.SeccompProfile.Type))
		if securityContext.SeccompProfile.LocalhostProfile != nil {
			builder.WriteString(fmt.Sprintf("              localhostProfile: %s\n", *securityContext.SeccompProfile.LocalhostProfile))
		}
	}
	return builder.String()
}

func stringPtr(value string) *string {
	return &value
}
