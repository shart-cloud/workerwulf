import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wDyn01: Probe = async ({ runId }) => {
  const details: Record<string, unknown> = {};
  const g = globalThis as Record<string, unknown>;

  let evalAvailable = false;
  let canModifyGlobals = false;
  const marker = `wulf-dyn-marker-${Date.now().toString(36)}`;
  const previousMarker = g.__wulfEvalMarker;

  // Step 1: basic expression
  try {
    const result = eval("1 + 1");
    details.eval_basic_expression = result;
    evalAvailable = true;
  } catch (err) {
    details.eval_basic_expression = {
      error: err instanceof Error ? err.message : String(err),
      error_name: err instanceof Error ? err.name : "unknown",
    };
  }

  // Step 2: side-effecting eval
  try {
    eval(`globalThis.__wulfEvalMarker = "${marker}"`);
    const retrieved = g.__wulfEvalMarker;
    canModifyGlobals = retrieved === marker;
    details.eval_side_effect = {
      marker_set: marker,
      marker_retrieved: retrieved,
      modified_globals: canModifyGlobals,
    };
  } catch (err) {
    details.eval_side_effect = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Step 3: multi-line eval with return
  try {
    const result = eval(`
      let x = 0;
      for (let i = 0; i < 1000000; i++) x += i;
      x;
    `);
    details.eval_multi_line = { result, correct: result === 499999500000 };
  } catch (err) {
    details.eval_multi_line = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Step 4: eval with try/catch (nested eval)
  try {
    const result = eval("(() => { try { throw new Error('inner'); } catch(e) { return e.message; } })()");
    details.eval_nested_try_catch = { result };
  } catch (err) {
    details.eval_nested_try_catch = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  return base({
    test_id: "W-DYN-01",
    track: "worker",
    description: "Test eval() availability and side-effect persistence",
    result: evalAvailable ? "accessible" : "blocked",
    severity: evalAvailable ? "medium" : "informational",
    run_id: runId,
    details: {
      eval_available: evalAvailable,
      can_modify_globals: canModifyGlobals,
      previous_eval_marker: previousMarker ?? null,
      eval_marker_persists: previousMarker !== undefined,
      ...details,
    },
    comparison: {
      aws_lambda: "accessible (full eval support)",
      azure_functions: "accessible (full eval support)",
      gcp_functions: "accessible (full eval support)",
    },
  });
};
