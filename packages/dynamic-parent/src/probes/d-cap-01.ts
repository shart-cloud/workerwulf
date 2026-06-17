import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dCap01: Probe = async ({ env, runId }) => {
  // Parent's globals snapshot for comparison
  const parentGlobals = Object.getOwnPropertyNames(globalThis as object).sort();

  const stub = loadChild(env);
  const { body } = await invokeChild(stub, "enumerate-globals");
  const childData = (body as { ok: boolean; data: { names: string[] } }).data;
  const childGlobals = childData.names;

  const onlyInParent = parentGlobals.filter((n) => !childGlobals.includes(n));
  const onlyInChild = childGlobals.filter((n) => !parentGlobals.includes(n));
  const sameSet =
    onlyInParent.length === 0 && onlyInChild.length === 0;

  return base({
    test_id: "D-CAP-01",
    track: "dynamic",
    description: "Compare child isolate globalThis to parent's",
    result: sameSet ? "informational" : "partial",
    severity: "informational",
    run_id: runId,
    details: {
      parent_count: parentGlobals.length,
      child_count: childGlobals.length,
      only_in_parent: onlyInParent,
      only_in_child: onlyInChild,
    },
  });
};
