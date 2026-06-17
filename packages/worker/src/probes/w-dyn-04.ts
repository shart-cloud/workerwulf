import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wDyn04: Probe = async ({ runId }) => {
  return base({
    test_id: "W-DYN-04",
    track: "worker",
    description: "Repeat eval() availability test inside a Dynamic Worker child",
    result: "informational",
    severity: "informational",
    run_id: runId,
    details: {
      implemented_in_worker_package: false,
      dynamic_parent_probe: "D-DYN-04",
      note: "This standard Worker has no Dynamic Worker loader binding. The equivalent child eval test is implemented in packages/dynamic-parent as D-DYN-04.",
    },
  });
};
