import type { Probe } from "./index.js";
import { base, delegatedResult, fetchDynamicProbe, getDoStub } from "./_helpers.js";

export const doDyn02: Probe = async ({ env, runId }) => {
  const dynamic = await fetchDynamicProbe({
    baseUrl: env.WULF_DYNAMIC_BASE_URL,
    fetcher: env.DYNAMIC_PARENT,
    testId: "D-DO-02",
    runId,
  });
  if (dynamic) {
    return delegatedResult({
      dynamic,
      testId: "DO-DYN-02",
      description: "Enumerate the DO stub's RPC surface from inside the sandbox",
      runId,
    });
  }

  // DO-DYN-02: Test whether a Dynamic Worker can access DO methods not
  // explicitly exposed. This requires a Dynamic Worker with a DO stub in
  // its env — for now we enumerate the DO stub from the parent perspective
  // as a baseline.
  const stub = getDoStub(env, "PREY_DO", "DO-DYN-02");

  const methods: string[] = [];
  let proto: object | null = Object.getPrototypeOf(stub);
  while (proto && proto !== Object.prototype) {
    for (const m of Object.getOwnPropertyNames(proto)) {
      if (m === "constructor") continue;
      const desc = Object.getOwnPropertyDescriptor(proto, m);
      if (desc && typeof desc.value === "function" && !methods.includes(m)) {
        methods.push(m);
      }
    }
    proto = Object.getPrototypeOf(proto);
  }

  return base({
    test_id: "DO-DYN-02",
    track: "durable",
    description:
      "Enumerate the DO stub's RPC surface from inside the sandbox",
    result: "partial",
    severity: "informational",
    run_id: runId,
    details: {
      stub_methods: methods.sort(),
      note: "Partial only: enumerated from the parent Worker perspective. Configure WULF_DYNAMIC_BASE_URL to delegate to packages/dynamic-parent D-DO-02.",
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
