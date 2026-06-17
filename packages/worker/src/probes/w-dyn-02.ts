import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wDyn02: Probe = async ({ runId }) => {
  const details: Record<string, unknown> = {};
  let available = false;

  // Test 1: basic return
  try {
    const fn = new Function("return 42");
    const result = fn();
    details.basic_return = { result, correct: result === 42 };
    available = true;
  } catch (err) {
    details.basic_return = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Test 2: with arguments
  try {
    const fn = new Function("x", "y", "return x * y");
    details.with_args = { result: fn(6, 7), correct: fn(6, 7) === 42 };
  } catch (err) {
    details.with_args = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Test 3: can access global scope
  try {
    const fn = new Function(
      "return typeof globalThis !== 'undefined' && globalThis === Function('return this')()",
    );
    details.got_global_scope = fn();
  } catch (err) {
    details.got_global_scope = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Test 4: can modify global scope
  const marker = `wulf-fn-marker-${Date.now().toString(36)}`;
  try {
    const fn = new Function("marker", `globalThis.__wulfFnMarker = marker; return marker;`);
    fn(marker);
    const retrieved = (globalThis as Record<string, unknown>).__wulfFnMarker;
    details.can_modify_globals = retrieved === marker;
    try {
      delete (globalThis as Record<string, unknown>).__wulfFnMarker;
    } catch {
      // ignore
    }
  } catch (err) {
    details.can_modify_globals = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Test 5: multiline function body
  try {
    const fn = new Function(`
      const a = [];
      for (let i = 0; i < 5; i++) a.push(i * i);
      return a;
    `);
    const result = fn();
    details.multi_line = {
      result,
      correct: JSON.stringify(result) === JSON.stringify([0, 1, 4, 9, 16]),
    };
  } catch (err) {
    details.multi_line = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  // Test 6: try to access constructor chain (Function.constructor)
  try {
    const fn = new Function("return this.constructor.constructor('return 1')()");
    const chainResult = fn();
    details.constructor_chain_access = chainResult === 1;
  } catch (err) {
    details.constructor_chain_access = {
      error: err instanceof Error ? err.message : String(err),
    };
  }

  return base({
    test_id: "W-DYN-02",
    track: "worker",
    description: "Test new Function() constructor code generation",
    result: available ? "accessible" : "blocked",
    severity: available ? "medium" : "informational",
    run_id: runId,
    details: {
      function_constructor_available: available,
      ...details,
    },
    comparison: {
      aws_lambda: "accessible (full Function constructor support)",
      azure_functions: "accessible (full Function constructor support)",
      gcp_functions: "accessible (full Function constructor support)",
    },
  });
};