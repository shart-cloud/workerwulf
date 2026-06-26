package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (in *SandboxWorker) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(SandboxWorker)
	*out = *in
	out.ObjectMeta = *in.ObjectMeta.DeepCopy()
	out.Spec = *in.Spec.DeepCopy()
	out.Status = *in.Status.DeepCopy()
	return out
}

func (in *SandboxWorkerList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(SandboxWorkerList)
	*out = *in
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]SandboxWorker, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].DeepCopy()
		}
	}
	return out
}

func (in *SandboxWorker) DeepCopy() *SandboxWorker {
	if in == nil {
		return nil
	}
	return in.DeepCopyObject().(*SandboxWorker)
}

func (in *SandboxWorkerSpec) DeepCopy() *SandboxWorkerSpec {
	if in == nil {
		return nil
	}
	out := new(SandboxWorkerSpec)
	*out = *in
	out.Script = *in.Script.DeepCopy()
	out.Bindings = *in.Bindings.DeepCopy()
	if in.CompatibilityFlags != nil {
		out.CompatibilityFlags = append([]string(nil), in.CompatibilityFlags...)
	}
	return out
}

func (in *ScriptSource) DeepCopy() *ScriptSource {
	if in == nil {
		return nil
	}
	out := new(ScriptSource)
	*out = *in
	if in.ConfigMapRef != nil {
		out.ConfigMapRef = &KeyRef{Name: in.ConfigMapRef.Name, Key: in.ConfigMapRef.Key}
	}
	if in.Git != nil {
		out.Git = &GitScriptRef{Repo: in.Git.Repo, Path: in.Git.Path, Ref: in.Git.Ref}
	}
	return out
}

func (in *WorkerBindings) DeepCopy() *WorkerBindings {
	if in == nil {
		return nil
	}
	out := new(WorkerBindings)
	*out = *in
	if in.Vars != nil {
		out.Vars = make(map[string]string, len(in.Vars))
		for key, value := range in.Vars {
			out.Vars[key] = value
		}
	}
	if in.Services != nil {
		out.Services = append([]ServiceBinding(nil), in.Services...)
	}
	return out
}

func (in *SandboxWorkerStatus) DeepCopy() *SandboxWorkerStatus {
	if in == nil {
		return nil
	}
	out := new(SandboxWorkerStatus)
	*out = *in
	if in.StartedAt != nil {
		out.StartedAt = in.StartedAt.DeepCopy()
	}
	if in.HardeningApplied.CapabilitiesDrop != nil {
		out.HardeningApplied.CapabilitiesDrop = append([]string(nil), in.HardeningApplied.CapabilitiesDrop...)
	}
	if in.Conditions != nil {
		out.Conditions = append([]metav1.Condition(nil), in.Conditions...)
	}
	return out
}

func (in *HardeningProfile) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(HardeningProfile)
	*out = *in
	out.ObjectMeta = *in.ObjectMeta.DeepCopy()
	out.Spec = *in.Spec.DeepCopy()
	out.Status = *in.Status.DeepCopy()
	return out
}

func (in *HardeningProfileList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(HardeningProfileList)
	*out = *in
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]HardeningProfile, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].DeepCopy()
		}
	}
	return out
}

func (in *HardeningProfile) DeepCopy() *HardeningProfile {
	if in == nil {
		return nil
	}
	return in.DeepCopyObject().(*HardeningProfile)
}

func (in *HardeningProfileSpec) DeepCopy() *HardeningProfileSpec {
	if in == nil {
		return nil
	}
	out := new(HardeningProfileSpec)
	*out = *in
	if in.AllowPrivilegeEscalation != nil {
		out.AllowPrivilegeEscalation = new(bool)
		*out.AllowPrivilegeEscalation = *in.AllowPrivilegeEscalation
	}
	if in.CapabilitiesDrop != nil {
		out.CapabilitiesDrop = append([]corev1.Capability(nil), in.CapabilitiesDrop...)
	}
	if in.CapabilitiesAdd != nil {
		out.CapabilitiesAdd = append([]corev1.Capability(nil), in.CapabilitiesAdd...)
	}
	return out
}

func (in *HardeningProfileStatus) DeepCopy() *HardeningProfileStatus {
	if in == nil {
		return nil
	}
	out := new(HardeningProfileStatus)
	*out = *in
	if in.Conditions != nil {
		out.Conditions = append([]metav1.Condition(nil), in.Conditions...)
	}
	return out
}
