package render

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"sigs.k8s.io/yaml"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-operator/operator/api/v1alpha1"
)

const DefaultImage = "ghcr.io/jlgore/wulf-operator-workerd:0.1.0"
const NetworkPolicyDenyAllEgress = "deny-all-egress"

// TetragonPolicyWorkerdSyscalls is the only supported HardeningProfile
// tetragonPolicyRef. It renders a per-worker TracingPolicyNamespaced that
// traces the workerd binary's openat/connect/execve/mmap syscalls. Like
// networkPolicyRef, any other value fails closed rather than silently
// rendering nothing.
const TetragonPolicyWorkerdSyscalls = "workerd-syscalls"

// DefaultInspectorPort is the V8 inspector (Chrome DevTools Protocol) port
// workerd binds when spec.runtime.v8Inspector is set.
const DefaultInspectorPort = 9229

type Options struct {
	Image            string
	HardeningProfile *wulfv1alpha1.HardeningProfileSpec
}

type Object struct {
	Kind string
	Name string
	YAML string
}

func RenderSandboxWorker(worker wulfv1alpha1.SandboxWorker, opts Options) ([]Object, error) {
	normalized, err := normalize(worker, opts)
	if err != nil {
		return nil, err
	}

	config, err := renderWorkerdConfig(normalized)
	if err != nil {
		return nil, err
	}

	configMap, err := renderTemplate("configmap", configMapTemplate, map[string]any{
		"Name":       normalized.ConfigMapName,
		"Namespace":  normalized.Namespace,
		"LabelPairs": normalized.LabelPairs,
		"Config":     indentBlock(config, 4),
		"Script":     indentBlock(normalized.InlineScript, 4),
	})
	if err != nil {
		return nil, err
	}

	deployment, err := renderTemplate("deployment", deploymentTemplate, normalized)
	if err != nil {
		return nil, err
	}

	objects := []Object{
		{Kind: "ConfigMap", Name: normalized.ConfigMapName, YAML: configMap},
		{Kind: "Deployment", Name: normalized.Name, YAML: deployment},
	}

	if normalized.ExposureType != "None" {
		service, err := renderTemplate("service", serviceTemplate, normalized)
		if err != nil {
			return nil, err
		}
		objects = append(objects, Object{Kind: "Service", Name: normalized.Name, YAML: service})
	}

	if normalized.NetworkPolicyRef != "" {
		networkPolicy, err := renderTemplate("networkpolicy", networkPolicyTemplate, normalized)
		if err != nil {
			return nil, err
		}
		objects = append(objects, Object{Kind: "NetworkPolicy", Name: normalized.NetworkPolicyName, YAML: networkPolicy})
	}

	if normalized.TetragonPolicyRef != "" {
		tracingYAML, err := yaml.Marshal(tracingPolicyResource(normalized).Object)
		if err != nil {
			return nil, err
		}
		objects = append(objects, Object{Kind: "TracingPolicyNamespaced", Name: normalized.TetragonPolicyName, YAML: string(tracingYAML)})
	}

	return objects, nil
}

type normalizedWorker struct {
	Name               string
	Namespace          string
	Image              string
	ConfigMapName      string
	InlineScript       string
	CompatibilityDate  string
	CompatibilityFlags []string
	Labels             map[string]string
	LabelPairs         []labelPair
	Vars               []bindingVar
	Services           []serviceBinding
	HardeningProfile   string
	HardeningSpec      *wulfv1alpha1.HardeningProfileSpec
	ExposureType       string
	Port               int
	CPURequest         string
	MemoryRequest      string
	CPULimit           string
	MemoryLimit        string
	SecurityContext    string
	NetworkPolicyRef   string
	NetworkPolicyName  string
	TetragonPolicyRef  string
	TetragonPolicyName string
	ResultSinkURL      string
	V8Inspector        bool
	InspectorPort      int
}

type labelPair struct {
	Key   string
	Value string
}

type bindingVar struct {
	Name  string
	Value string
}

type serviceBinding struct {
	Name      string
	WorkerRef string
}

func normalize(worker wulfv1alpha1.SandboxWorker, opts Options) (normalizedWorker, error) {
	if worker.Name == "" {
		return normalizedWorker{}, errors.New("metadata.name is required")
	}
	if worker.Spec.Script.Inline == "" {
		return normalizedWorker{}, errors.New("only spec.script.inline is supported in the current renderer")
	}
	if err := rejectUnsupported(worker.Spec); err != nil {
		return normalizedWorker{}, err
	}

	namespace := worker.Namespace
	if namespace == "" {
		namespace = "wulf-system"
	}

	image := opts.Image
	if image == "" {
		image = DefaultImage
	}

	port := worker.Spec.Exposure.Port
	if port == 0 {
		port = 8080
	}
	exposureType := worker.Spec.Exposure.Type
	if exposureType == "" {
		exposureType = "ClusterIP"
	}

	profile := worker.Spec.Hardening.Profile
	if profile == "" {
		profile = "naked"
	}
	hardeningSpec := hardeningProfileSpecFor(profile, opts.HardeningProfile)
	networkPolicyRef, err := networkPolicyRefFor(hardeningSpec)
	if err != nil {
		return normalizedWorker{}, err
	}
	tetragonPolicyRef, err := tetragonPolicyRefFor(hardeningSpec)
	if err != nil {
		return normalizedWorker{}, err
	}

	labels := map[string]string{
		"app.kubernetes.io/name":               worker.Name,
		"app.kubernetes.io/part-of":            "wulf-operator",
		"wulf.jaredgore.com/hardening-profile": profile,
	}
	for key, value := range worker.Labels {
		labels[key] = value
	}

	resources := worker.Spec.Runtime.Resources
	normalized := normalizedWorker{
		Name:               worker.Name,
		Namespace:          namespace,
		Image:              image,
		ConfigMapName:      worker.Name + "-config",
		InlineScript:       worker.Spec.Script.Inline,
		CompatibilityDate:  worker.Spec.CompatibilityDate,
		CompatibilityFlags: worker.Spec.CompatibilityFlags,
		Labels:             labels,
		LabelPairs:         sortedLabels(labels),
		Vars:               sortedVars(worker.Spec.Bindings.Vars),
		Services:           sortedServices(worker.Spec.Bindings.Services),
		HardeningProfile:   profile,
		HardeningSpec:      hardeningSpec,
		ExposureType:       exposureType,
		Port:               port,
		CPURequest:         defaultString(resources.Requests.CPU, "100m"),
		MemoryRequest:      defaultString(resources.Requests.Memory, "128Mi"),
		CPULimit:           defaultString(resources.Limits.CPU, "500m"),
		MemoryLimit:        defaultString(resources.Limits.Memory, "256Mi"),
		SecurityContext:    securityContextFor(profile, hardeningSpec),
		NetworkPolicyRef:   networkPolicyRef,
		NetworkPolicyName:  NetworkPolicyName(worker),
		TetragonPolicyRef:  tetragonPolicyRef,
		TetragonPolicyName: TetragonPolicyName(worker),
		ResultSinkURL:      worker.Spec.Instrumentation.ResultSink.Endpoint,
		V8Inspector:        worker.Spec.Runtime.V8Inspector,
		InspectorPort:      DefaultInspectorPort,
	}
	if normalized.CompatibilityDate == "" {
		normalized.CompatibilityDate = "2024-09-23"
	}

	return normalized, nil
}

func sortedLabels(labels map[string]string) []labelPair {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]labelPair, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, labelPair{Key: key, Value: labels[key]})
	}
	return pairs
}

func sortedVars(vars map[string]string) []bindingVar {
	keys := make([]string, 0, len(vars)+3)
	for key := range vars {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]bindingVar, 0, len(keys)+3)
	for _, key := range keys {
		out = append(out, bindingVar{Name: key, Value: vars[key]})
	}
	return out
}

func sortedServices(services []wulfv1alpha1.ServiceBinding) []serviceBinding {
	out := make([]serviceBinding, 0, len(services))
	for _, service := range services {
		out = append(out, serviceBinding{Name: service.Name, WorkerRef: service.WorkerRef})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// rejectUnsupported fails loudly on spec fields the CRD advertises but the
// renderer does not yet honor. Silently dropping them lets an operator believe
// they applied an isolate cap or a request timeout that never took effect —
// worse than a hard error. Wire a field here (and delete its check) the moment
// the renderer actually implements it.
func rejectUnsupported(spec wulfv1alpha1.SandboxWorkerSpec) error {
	if spec.Script.Git != nil {
		return errors.New("spec.script.git is not implemented; use spec.script.inline")
	}
	if spec.Script.ConfigMapRef != nil {
		return errors.New("spec.script.configMapRef is not implemented; use spec.script.inline")
	}
	if spec.Runtime.MaxIsolates != 0 {
		return errors.New("spec.runtime.maxIsolates is not implemented")
	}
	if spec.Runtime.RequestTimeoutMs != 0 {
		return errors.New("spec.runtime.requestTimeoutMs is not implemented")
	}
	if spec.Runtime.CoLocateWith != "" {
		return errors.New("spec.runtime.coLocateWith is not implemented")
	}
	if spec.Instrumentation.TracingPolicy != "" {
		return errors.New("spec.instrumentation.tracingPolicy is not applied by the operator; apply the Tetragon TracingPolicy out of band")
	}
	return nil
}

func networkPolicyRefFor(spec *wulfv1alpha1.HardeningProfileSpec) (string, error) {
	if spec == nil || spec.NetworkPolicyRef == "" {
		return "", nil
	}
	switch spec.NetworkPolicyRef {
	case NetworkPolicyDenyAllEgress:
		return spec.NetworkPolicyRef, nil
	default:
		return "", fmt.Errorf("unsupported networkPolicyRef %q", spec.NetworkPolicyRef)
	}
}

func tetragonPolicyRefFor(spec *wulfv1alpha1.HardeningProfileSpec) (string, error) {
	if spec == nil || spec.TetragonPolicyRef == "" {
		return "", nil
	}
	switch spec.TetragonPolicyRef {
	case TetragonPolicyWorkerdSyscalls:
		return spec.TetragonPolicyRef, nil
	default:
		return "", fmt.Errorf("unsupported tetragonPolicyRef %q", spec.TetragonPolicyRef)
	}
}

func renderWorkerdConfig(worker normalizedWorker) (string, error) {
	return renderTemplate("workerd", workerdConfigTemplate, map[string]any{
		"CompatibilityDate":  quoteCapnp(worker.CompatibilityDate),
		"CompatibilityFlags": quoteList(worker.CompatibilityFlags),
		"Vars":               capnpVars(worker),
		"Services":           worker.Services,
	})
}

func capnpVars(worker normalizedWorker) []bindingVar {
	seen := map[string]bool{}
	out := make([]bindingVar, 0, len(worker.Vars)+3)
	add := func(name, value string) {
		if seen[name] {
			return
		}
		seen[name] = true
		out = append(out, bindingVar{Name: name, Value: value})
	}

	add("WORKER_NAME", bindingValue(worker.Vars, "WORKER_NAME", worker.Name))
	add("HARDENING_PROFILE", bindingValue(worker.Vars, "HARDENING_PROFILE", worker.HardeningProfile))
	add("RESULT_SINK_URL", bindingValue(worker.Vars, "RESULT_SINK_URL", worker.ResultSinkURL))
	for _, variable := range worker.Vars {
		add(variable.Name, variable.Value)
	}
	return out
}

func bindingValue(vars []bindingVar, name, fallback string) string {
	for _, variable := range vars {
		if variable.Name == name {
			return variable.Value
		}
	}
	return fallback
}

func quoteList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, quoteCapnp(value))
	}
	return out
}

func quoteCapnp(value string) string {
	return strconv.Quote(value)
}

func renderTemplate(name, source string, data any) (string, error) {
	tmpl, err := template.New(name).Funcs(template.FuncMap{
		"quote": quoteCapnp,
	}).Parse(source)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n") + "\n", nil
}

func indentBlock(value string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	lines := strings.Split(strings.TrimRight(value, "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func YAMLStream(objects []Object) string {
	var builder strings.Builder
	for i, object := range objects {
		if i > 0 {
			builder.WriteString("---\n")
		}
		builder.WriteString(object.YAML)
	}
	return builder.String()
}

func MustRenderSandboxWorker(worker wulfv1alpha1.SandboxWorker, opts Options) string {
	objects, err := RenderSandboxWorker(worker, opts)
	if err != nil {
		panic(fmt.Sprintf("render sandbox worker: %v", err))
	}
	return YAMLStream(objects)
}

const workerdConfigTemplate = `using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .mainWorker),
    (
      name = "internet",
      network = (
        allow = ["public"]
      )
    )
  ],

  sockets = [
    (
      name = "http",
      address = "*:8080",
      http = (),
      service = "main"
    )
  ]
);

const mainWorker :Workerd.Worker = (
  modules = [
    (
      name = "worker.js",
      esModule = embed "../script/worker.js"
    )
  ],
  compatibilityDate = {{ .CompatibilityDate }},
{{- if .CompatibilityFlags }}
  compatibilityFlags = [{{ range $i, $flag := .CompatibilityFlags }}{{ if $i }}, {{ end }}{{ $flag }}{{ end }}],
{{- end }}
  globalOutbound = "internet",
  bindings = [
{{- range .Vars }}
    (name = {{ quote .Name }}, text = {{ quote .Value }}),
{{- end }}
{{- range .Services }}
    (name = {{ quote .Name }}, service = {{ quote .WorkerRef }}),
{{- end }}
  ]
);
`

const configMapTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
  labels:
{{- range .LabelPairs }}
    {{ .Key }}: {{ .Value }}
{{- end }}
data:
  workerd.capnp: |
{{ .Config }}
  worker.js: |
{{ .Script }}
`

const deploymentTemplate = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
  labels:
{{- range .LabelPairs }}
    {{ .Key }}: {{ .Value }}
{{- end }}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ .Name }}
  template:
    metadata:
      labels:
{{- range .LabelPairs }}
        {{ .Key }}: {{ .Value }}
{{- end }}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: workerd
          image: {{ .Image }}
          imagePullPolicy: IfNotPresent
          args:
            - serve
            - /etc/workerd/config/workerd.capnp
            - -I
            - /usr/local/lib/node_modules/workerd
{{- if .V8Inspector }}
            - --inspector-addr=0.0.0.0:{{ .InspectorPort }}
{{- end }}
{{ .SecurityContext }}
          ports:
            - name: http
              containerPort: 8080
{{- if .V8Inspector }}
            - name: inspector
              containerPort: {{ .InspectorPort }}
{{- end }}
          readinessProbe:
            tcpSocket:
              port: http
            initialDelaySeconds: 2
            periodSeconds: 5
          livenessProbe:
            tcpSocket:
              port: http
            initialDelaySeconds: 10
            periodSeconds: 20
          resources:
            requests:
              cpu: {{ .CPURequest }}
              memory: {{ .MemoryRequest }}
            limits:
              cpu: {{ .CPULimit }}
              memory: {{ .MemoryLimit }}
          volumeMounts:
            - name: workerd-config
              mountPath: /etc/workerd
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: workerd-config
          configMap:
            name: {{ .ConfigMapName }}
            items:
              - key: workerd.capnp
                path: config/workerd.capnp
              - key: worker.js
                path: script/worker.js
        - name: tmp
          emptyDir: {}
`

const serviceTemplate = `apiVersion: v1
kind: Service
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
  labels:
{{- range .LabelPairs }}
    {{ .Key }}: {{ .Value }}
{{- end }}
spec:
  type: {{ .ExposureType }}
  selector:
    app.kubernetes.io/name: {{ .Name }}
  ports:
    - name: http
      port: {{ .Port }}
      targetPort: http
{{- if .V8Inspector }}
    - name: inspector
      port: {{ .InspectorPort }}
      targetPort: inspector
{{- end }}
`

const networkPolicyTemplate = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ .NetworkPolicyName }}
  namespace: {{ .Namespace }}
  labels:
{{- range .LabelPairs }}
    {{ .Key }}: {{ .Value }}
{{- end }}
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: {{ .Name }}
  policyTypes:
    - Egress
  egress: []
`
