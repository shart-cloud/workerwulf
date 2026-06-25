using Workerd = import "/workerd/workerd.capnp";

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
      name = "rt-001-syscall-smoke.js",
      esModule = embed "../probes/runtime/rt-001-syscall-smoke.js"
    )
  ],
  compatibilityDate = "2024-09-23",
  compatibilityFlags = ["nodejs_compat"],
  globalOutbound = "internet",
  bindings = [
    (name = "WORKER_NAME", text = "workerd-rt-001"),
    (name = "HARDENING_PROFILE", text = "naked"),
    (name = "RESULT_SINK_URL", text = ""),
    (name = "EGRESS_TARGET", text = "")
  ]
);
