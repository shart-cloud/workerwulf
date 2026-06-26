package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	Group   = "wulf.jaredgore.com"
	Version = "v1alpha1"

	KindSandboxWorker    = "SandboxWorker"
	KindHardeningProfile = "HardeningProfile"
)

var SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

var SchemeBuilder = runtime.NewSchemeBuilder(func(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		SchemeGroupVersion,
		&SandboxWorker{},
		&SandboxWorkerList{},
		&HardeningProfile{},
		&HardeningProfileList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
})

func AddToScheme(scheme *runtime.Scheme) error {
	return SchemeBuilder.AddToScheme(scheme)
}

type SandboxWorker struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SandboxWorkerSpec   `json:"spec,omitempty"`
	Status SandboxWorkerStatus `json:"status,omitempty"`
}

type SandboxWorkerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []SandboxWorker `json:"items"`
}

type SandboxWorkerSpec struct {
	Script             ScriptSource        `json:"script"`
	CompatibilityDate  string              `json:"compatibilityDate,omitempty"`
	CompatibilityFlags []string            `json:"compatibilityFlags,omitempty"`
	Bindings           WorkerBindings      `json:"bindings,omitempty"`
	Hardening          SandboxHardening    `json:"hardening,omitempty"`
	Instrumentation    InstrumentationSpec `json:"instrumentation,omitempty"`
	Runtime            RuntimeSpec         `json:"runtime,omitempty"`
	Exposure           ExposureSpec        `json:"exposure,omitempty"`
}

type ScriptSource struct {
	Inline       string        `json:"inline,omitempty"`
	ConfigMapRef *KeyRef       `json:"configMapRef,omitempty"`
	Git          *GitScriptRef `json:"git,omitempty"`
}

type KeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type GitScriptRef struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
	Ref  string `json:"ref,omitempty"`
}

type WorkerBindings struct {
	Vars     map[string]string `json:"vars,omitempty"`
	Services []ServiceBinding  `json:"services,omitempty"`
}

type ServiceBinding struct {
	Name      string `json:"name"`
	WorkerRef string `json:"workerRef"`
}

type SandboxHardening struct {
	Profile string `json:"profile,omitempty"`
}

type InstrumentationSpec struct {
	TracingPolicy string     `json:"tracingPolicy,omitempty"`
	ResultSink    ResultSink `json:"resultSink,omitempty"`
}

type ResultSink struct {
	Type     string `json:"type,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

type RuntimeSpec struct {
	Resources        ResourceSpec `json:"resources,omitempty"`
	MaxIsolates      int          `json:"maxIsolates,omitempty"`
	RequestTimeoutMs int          `json:"requestTimeoutMs,omitempty"`
	CoLocateWith     string       `json:"coLocateWith,omitempty"`
	V8Inspector      bool         `json:"v8Inspector,omitempty"`
}

type ResourceSpec struct {
	Requests ResourceList `json:"requests,omitempty"`
	Limits   ResourceList `json:"limits,omitempty"`
}

type ResourceList struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

type ExposureSpec struct {
	Type string `json:"type,omitempty"`
	Port int    `json:"port,omitempty"`
}

type SandboxWorkerStatus struct {
	Phase                  string             `json:"phase,omitempty"`
	PodName                string             `json:"podName,omitempty"`
	PodIP                  string             `json:"podIP,omitempty"`
	NodeName               string             `json:"nodeName,omitempty"`
	StartedAt              *metav1.Time       `json:"startedAt,omitempty"`
	LastObservedGeneration int64              `json:"lastObservedGeneration,omitempty"`
	HardeningApplied       HardeningApplied   `json:"hardeningApplied,omitempty"`
	Conditions             []metav1.Condition `json:"conditions,omitempty"`
}

type HardeningApplied struct {
	Profile          string   `json:"profile,omitempty"`
	SeccompProfile   string   `json:"seccompProfile,omitempty"`
	CapabilitiesDrop []string `json:"capabilitiesDrop,omitempty"`
	RunAsNonRoot     bool     `json:"runAsNonRoot,omitempty"`
	ReadOnlyRootFS   bool     `json:"readOnlyRootFilesystem,omitempty"`
	NetworkPolicy    string   `json:"networkPolicy,omitempty"`
	TetragonPolicy   string   `json:"tetragonPolicy,omitempty"`
	TetragonEnforce  string   `json:"tetragonEnforce,omitempty"`
}

type HardeningProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HardeningProfileSpec   `json:"spec,omitempty"`
	Status HardeningProfileStatus `json:"status,omitempty"`
}

type HardeningProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []HardeningProfile `json:"items"`
}

type HardeningProfileSpec struct {
	Description              string              `json:"description,omitempty"`
	Seccomp                  SeccompSpec         `json:"seccomp,omitempty"`
	AllowPrivilegeEscalation *bool               `json:"allowPrivilegeEscalation,omitempty"`
	CapabilitiesDrop         []corev1.Capability `json:"capabilitiesDrop,omitempty"`
	CapabilitiesAdd          []corev1.Capability `json:"capabilitiesAdd,omitempty"`
	ReadOnlyRootFilesystem   bool                `json:"readOnlyRootFilesystem,omitempty"`
	RunAsNonRoot             bool                `json:"runAsNonRoot,omitempty"`
	RunAsUser                int64               `json:"runAsUser,omitempty"`
	NetworkPolicyRef         string              `json:"networkPolicyRef,omitempty"`
	TetragonPolicyRef        string              `json:"tetragonPolicyRef,omitempty"`
	TetragonEnforceRef       string              `json:"tetragonEnforceRef,omitempty"`
}

type HardeningProfileStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

type SeccompSpec struct {
	Type       string `json:"type,omitempty"`
	ProfileRef string `json:"profileRef,omitempty"`
}

func NewSandboxWorker(name, namespace string) SandboxWorker {
	return SandboxWorker{
		TypeMeta: metav1.TypeMeta{
			APIVersion: SchemeGroupVersion.String(),
			Kind:       KindSandboxWorker,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}
