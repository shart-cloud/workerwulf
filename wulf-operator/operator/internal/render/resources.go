package render

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-operator/operator/api/v1alpha1"
)

// TracingPolicyGVK is the Tetragon namespaced tracing-policy kind the operator
// renders. It is applied as an unstructured object so the operator does not take
// a build-time dependency on Tetragon's Go API. Resolved at runtime via the
// cluster RESTMapper, so it only needs the Tetragon CRDs installed when a
// HardeningProfile actually sets tetragonPolicyRef.
var TracingPolicyGVK = schema.GroupVersionKind{
	Group:   "cilium.io",
	Version: "v1alpha1",
	Kind:    "TracingPolicyNamespaced",
}

type Resources struct {
	ConfigMap         *corev1.ConfigMap
	Deployment        *appsv1.Deployment
	Service           *corev1.Service
	NetworkPolicy     *networkingv1.NetworkPolicy
	TracingPolicy     *unstructured.Unstructured
	EnforcementPolicy *unstructured.Unstructured
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
					// A sandboxed worker has no business talking to the API server.
					// If a worker escapes the V8 isolate, denying the mounted
					// ServiceAccount token removes the most obvious pivot off the pod.
					AutomountServiceAccountToken: boolPtr(false),
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
							// TCP probes, not HTTP: GET / on this worker IS the research probe
							// (it returns the ProbeResult and generates the traced syscalls).
							// An httpGet health check would pollute every observation, so we
							// only check that the socket is accepting connections.
							ReadinessProbe: tcpProbe(2, 5),
							LivenessProbe:  tcpProbe(10, 20),
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
								// Writable scratch so a profile can set
								// readOnlyRootFilesystem without breaking workerd's
								// temp-file use.
								{Name: "tmp", MountPath: "/tmp"},
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
						{
							Name:         "tmp",
							VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
						},
					},
				},
			},
		},
	}

	if normalized.V8Inspector {
		container := &deployment.Spec.Template.Spec.Containers[0]
		container.Args = append(container.Args, fmt.Sprintf("--inspector-addr=0.0.0.0:%d", normalized.InspectorPort))
		container.Ports = append(container.Ports, corev1.ContainerPort{Name: "inspector", ContainerPort: int32(normalized.InspectorPort)})
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
		if normalized.V8Inspector {
			service.Spec.Ports = append(service.Spec.Ports, corev1.ServicePort{
				Name:       "inspector",
				Port:       int32(normalized.InspectorPort),
				TargetPort: intstr.FromString("inspector"),
			})
		}
	}

	networkPolicy := networkPolicyResourceFor(normalized, labels)

	var tracingPolicy *unstructured.Unstructured
	if normalized.TetragonPolicyRef != "" {
		tracingPolicy = tracingPolicyResource(normalized)
	}

	var enforcementPolicy *unstructured.Unstructured
	if normalized.TetragonEnforceRef != "" {
		enforcementPolicy = enforcementPolicyResource(normalized)
	}

	return Resources{ConfigMap: configMap, Deployment: deployment, Service: service, NetworkPolicy: networkPolicy, TracingPolicy: tracingPolicy, EnforcementPolicy: enforcementPolicy}, nil
}

// TetragonPolicyName is the deterministic name of the per-worker
// TracingPolicyNamespaced rendered when the resolved HardeningProfile sets
// tetragonPolicyRef.
func TetragonPolicyName(worker wulfv1alpha1.SandboxWorker) string {
	return worker.Name + "-tracing"
}

// tracingPolicyResource builds the per-worker TracingPolicyNamespaced. It is the
// single source of truth for both render paths: the typed controller path uses
// the object directly, and the string preview path marshals it to YAML. The
// policy is scoped to this worker's pods via podSelector and to the workerd
// binary via matchBinaries, so it neither traces nor is garbage-collected with
// any other worker. The __x64_sys_* kprobes are x86_64-specific; on other
// architectures the call names must change.
func tracingPolicyResource(worker normalizedWorker) *unstructured.Unstructured {
	binaries := workerdBinaryValues()
	arg := func(index int64, argType string) interface{} {
		return map[string]interface{}{"index": index, "type": argType}
	}
	kprobe := func(call string, args ...interface{}) interface{} {
		return map[string]interface{}{
			"call":    call,
			"syscall": true,
			"selectors": []interface{}{
				map[string]interface{}{
					"matchBinaries": []interface{}{
						map[string]interface{}{"operator": "In", "values": binaries},
					},
				},
			},
			"args": args,
		}
	}

	labelsObj := make(map[string]interface{}, len(worker.Labels))
	for key, value := range worker.Labels {
		labelsObj[key] = value
	}

	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": TracingPolicyGVK.GroupVersion().String(),
		"kind":       TracingPolicyGVK.Kind,
		"metadata": map[string]interface{}{
			"name":      worker.TetragonPolicyName,
			"namespace": worker.Namespace,
			"labels":    labelsObj,
		},
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{"app.kubernetes.io/name": worker.Name},
			},
			"kprobes": []interface{}{
				kprobe("__x64_sys_openat", arg(1, "string"), arg(2, "int")),
				kprobe("__x64_sys_connect", arg(1, "sockaddr")),
				kprobe("__x64_sys_execve", arg(0, "string")),
				kprobe("__x64_sys_mmap", arg(2, "int"), arg(3, "int")),
			},
		},
	}}
}

// workerdBinaryValues is the set of known workerd binary paths used to scope
// both the tracing and enforcement policies via matchBinaries, so a policy only
// hooks the workerd process and not unrelated binaries in the pod.
func workerdBinaryValues() []interface{} {
	return []interface{}{
		"/usr/local/bin/workerd",
		"/usr/local/lib/node_modules/workerd/bin/workerd",
		"/usr/local/lib/node_modules/workerd/node_modules/@cloudflare/workerd-linux-64/bin/workerd",
		"/usr/bin/workerd",
	}
}

// EnforcementPolicyName is the deterministic name of the per-worker enforcing
// TracingPolicyNamespaced rendered when the resolved HardeningProfile sets
// tetragonEnforceRef. It is distinct from TetragonPolicyName so a profile can
// both trace (-tracing) and enforce (-enforce) without the two policies
// colliding.
func EnforcementPolicyName(worker wulfv1alpha1.SandboxWorker) string {
	return worker.Name + "-enforce"
}

// enforcementPolicyResource builds the per-worker enforcing
// TracingPolicyNamespaced. It uses Tetragon BPF-LSM hooks (spec.lsmhooks, not
// kprobes on the security_* functions) for the workerd binary and attaches an
// Override action that returns -EPERM, so a denied operation fails in-place while
// the worker keeps running — which lets a probe observe and report the denial.
// BPF-LSM hooks return access decisions natively, so Override does not depend on
// the kernel's error-injection allowlist the way a kprobe on a security_*
// function would; this was verified to enforce (and the worker to survive) on a
// Talos v1.7.0 Tetragon cluster with BPF-LSM enabled. The hook names carry no
// __x64_ prefix, so they are architecture-independent.
//
// The hook set is deliberately limited to operations workerd should never
// legitimately perform: socket_connect (all egress, including DNS),
// bprm_check_security (exec), and ptrace_access_check. file_open is intentionally
// NOT enforced here: matchBinaries scopes to workerd itself, so a blanket
// file_open Override would deny workerd's own config/script/library opens and
// break the worker. Meaningful file enforcement needs path-scoped matchArgs and
// is a separate follow-up.
//
// Like tracingPolicyResource this is the single source of truth for both the
// typed controller path and the string preview path, and is pod-selector +
// matchBinaries scoped to this worker only.
func enforcementPolicyResource(worker normalizedWorker) *unstructured.Unstructured {
	binaries := workerdBinaryValues()
	arg := func(index int64, argType string) interface{} {
		return map[string]interface{}{"index": index, "type": argType}
	}
	// Each LSM hook matches only the workerd binary and overrides the return
	// value with -1 (-EPERM), denying the operation at the LSM boundary.
	lsmHook := func(hook string, args ...interface{}) interface{} {
		return map[string]interface{}{
			"hook": hook,
			"args": args,
			"selectors": []interface{}{
				map[string]interface{}{
					"matchBinaries": []interface{}{
						map[string]interface{}{"operator": "In", "values": binaries},
					},
					"matchActions": []interface{}{
						map[string]interface{}{"action": "Override", "argError": int64(-1)},
					},
				},
			},
		}
	}

	labelsObj := make(map[string]interface{}, len(worker.Labels))
	for key, value := range worker.Labels {
		labelsObj[key] = value
	}

	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": TracingPolicyGVK.GroupVersion().String(),
		"kind":       TracingPolicyGVK.Kind,
		"metadata": map[string]interface{}{
			"name":      worker.TetragonEnforceName,
			"namespace": worker.Namespace,
			"labels":    labelsObj,
		},
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{"app.kubernetes.io/name": worker.Name},
			},
			"lsmhooks": []interface{}{
				lsmHook("socket_connect", arg(1, "sockaddr")),
				lsmHook("bprm_check_security", arg(0, "linux_binprm")),
				lsmHook("ptrace_access_check", arg(1, "int")),
			},
		},
	}}
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

func tcpProbe(initialDelaySeconds, periodSeconds int32) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString("http")},
		},
		InitialDelaySeconds: initialDelaySeconds,
		PeriodSeconds:       periodSeconds,
	}
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
	// In-cluster, profiles are always CR-driven (the controller resolves the
	// HardeningProfile and passes its spec). This built-in fallback exists only
	// for the wulf-operator-render CLI preview and MUST mirror a profile actually
	// shipped under deploy/profiles/. Do not add aspirational names here:
	// "bpf-lsm"/"full-lockdown" have no enforcement yet, and a name that renders
	// hardening it doesn't deliver is worse than a missing profile.
	switch profile {
	case "seccomp-baseline":
		allowPrivilegeEscalation := false
		return &wulfv1alpha1.HardeningProfileSpec{
			Seccomp:                  wulfv1alpha1.SeccompSpec{Type: string(corev1.SeccompProfileTypeRuntimeDefault)},
			AllowPrivilegeEscalation: &allowPrivilegeEscalation,
			CapabilitiesDrop:         []corev1.Capability{corev1.Capability("ALL")},
			ReadOnlyRootFilesystem:   true,
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
