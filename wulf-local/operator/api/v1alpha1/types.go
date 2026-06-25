package v1alpha1

const (
	GroupVersion = "wulf.jaredgore.com/v1alpha1"

	KindSandboxWorker    = "SandboxWorker"
	KindHardeningProfile = "HardeningProfile"
)

type ObjectMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type SandboxWorker struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ObjectMeta        `json:"metadata"`
	Spec       SandboxWorkerSpec `json:"spec"`
}

type SandboxWorkerSpec struct {
	Script             ScriptSource        `json:"script"`
	CompatibilityDate  string              `json:"compatibilityDate"`
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

type HardeningProfile struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Metadata   ObjectMeta           `json:"metadata"`
	Spec       HardeningProfileSpec `json:"spec"`
}

type HardeningProfileSpec struct {
	Description            string      `json:"description,omitempty"`
	Seccomp                SeccompSpec `json:"seccomp,omitempty"`
	CapabilitiesDrop       []string    `json:"capabilitiesDrop,omitempty"`
	CapabilitiesAdd        []string    `json:"capabilitiesAdd,omitempty"`
	ReadOnlyRootFilesystem bool        `json:"readOnlyRootFilesystem,omitempty"`
	RunAsNonRoot           bool        `json:"runAsNonRoot,omitempty"`
	RunAsUser              int64       `json:"runAsUser,omitempty"`
	NetworkPolicyRef       string      `json:"networkPolicyRef,omitempty"`
	TetragonPolicyRef      string      `json:"tetragonPolicyRef,omitempty"`
}

type SeccompSpec struct {
	Type       string `json:"type,omitempty"`
	ProfileRef string `json:"profileRef,omitempty"`
}

func NewSandboxWorker(name, namespace string) SandboxWorker {
	return SandboxWorker{
		APIVersion: GroupVersion,
		Kind:       KindSandboxWorker,
		Metadata: ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}
