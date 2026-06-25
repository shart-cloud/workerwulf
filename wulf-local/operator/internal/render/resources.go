package render

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-local/operator/api/v1alpha1"
)

type Resources struct {
	ConfigMap  *corev1.ConfigMap
	Deployment *appsv1.Deployment
	Service    *corev1.Service
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
							SecurityContext: securityContextResourceFor(normalized.HardeningProfile),
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

	return Resources{ConfigMap: configMap, Deployment: deployment, Service: service}, nil
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

func securityContextResourceFor(profile string) *corev1.SecurityContext {
	switch profile {
	case "seccomp-baseline", "seccomp-strict", "bpf-lsm", "full-lockdown":
		return &corev1.SecurityContext{
			AllowPrivilegeEscalation: boolPtr(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{corev1.Capability("ALL")},
			},
			RunAsNonRoot: boolPtr(true),
			RunAsUser:    int64Ptr(65532),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		}
	default:
		return nil
	}
}
