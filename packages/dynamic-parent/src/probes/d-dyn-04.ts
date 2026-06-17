import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dDyn04: Probe = async ({ env, runId }) => {
  const stub = loadChild(env);
  const { body, ok } = await invokeChild(stub, "dyn-eval");

  if (!ok) {
    return base({
      test_id: "D-DYN-04",
      track: "dynamic",
      description: "Test eval() and Function() constructor availability inside a Dynamic Worker child isolate",
      result: "error",
      severity: "informational",
      run_id: runId,
      details: {
        child_error: body,
      },
    });
  }

  const childData = (body as { ok: boolean; data: Record<string, unknown> }).data;

  const parentGlobals = Object.getOwnPropertyNames(globalThis as object);
  const parentHasEval = typeof eval !== "undefined";
  const parentHasFunction = typeof Function !== "undefined";

  let parentFnCtorAvail = false;
  let parentFnCtorResult: unknown = undefined;
  try {
    const fn = new Function("return 42");
    parentFnCtorAvail = true;
    parentFnCtorResult = fn();
  } catch {
    // ignore
  }

  const childResult = childData.eval_available;
  const childFnResult = childData.function_ctor_available;
  const sameAsParent =
    childResult === parentHasEval && childFnResult === parentFnCtorAvail;

  return base({
    test_id: "D-DYN-04",
    track: "dynamic",
    description: "Test eval() and Function() constructor availability inside a Dynamic Worker child isolate",
    result: "informational",
    severity: childResult ? "medium" : "informational",
    run_id: runId,
    details: {
      parent: {
        eval_available: parentHasEval,
        function_ctor_available: parentFnCtorAvail,
        function_ctor_result: parentFnCtorResult,
      },
      child: childData,
      same_as_parent: sameAsParent,
      note: childResult
        ? "eval() is available in Dynamic Worker child — untrusted code can generate and execute additional code at runtime"
        : "eval() is blocked in Dynamic Worker child — restricts code generation from inside sandbox",
    },
    comparison: {
      aws_lambda: "N/A (no equivalent sandbox)",
      azure_functions: "N/A (no equivalent sandbox)",
      gcp_functions: "N/A (no equivalent sandbox)",
    },
  });
};