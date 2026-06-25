package main

import (
	"fmt"
	"os"

	wulfv1alpha1 "github.com/jlgore/workerwulf/wulf-local/operator/api/v1alpha1"
	"github.com/jlgore/workerwulf/wulf-local/operator/internal/render"
)

func main() {
	worker := wulfv1alpha1.NewSandboxWorker("workerd-rt-001", "wulf-system")
	worker.Labels = map[string]string{
		"wulf.jaredgore.com/track":    "runtime-fingerprint",
		"wulf.jaredgore.com/probe-id": "P-WL-RT-001",
	}
	worker.Spec = wulfv1alpha1.SandboxWorkerSpec{
		Script: wulfv1alpha1.ScriptSource{
			Inline: `export default {
  fetch() {
    return Response.json({ ok: true, platform: "wulf-local" });
  },
};`,
		},
		CompatibilityDate:  "2024-09-23",
		CompatibilityFlags: []string{"nodejs_compat"},
		Bindings: wulfv1alpha1.WorkerBindings{
			Vars: map[string]string{
				"WORKER_NAME":       "workerd-rt-001",
				"HARDENING_PROFILE": "naked",
			},
		},
		Hardening: wulfv1alpha1.SandboxHardening{Profile: "naked"},
		Runtime: wulfv1alpha1.RuntimeSpec{
			Resources: wulfv1alpha1.ResourceSpec{
				Requests: wulfv1alpha1.ResourceList{CPU: "100m", Memory: "128Mi"},
				Limits:   wulfv1alpha1.ResourceList{CPU: "500m", Memory: "256Mi"},
			},
		},
		Exposure: wulfv1alpha1.ExposureSpec{Type: "ClusterIP", Port: 8080},
	}

	objects, err := render.RenderSandboxWorker(worker, render.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "render: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(render.YAMLStream(objects))
}
