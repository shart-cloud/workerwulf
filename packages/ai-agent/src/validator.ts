import { parse, type Node } from "acorn";
import * as walk from "acorn-walk";

export type ValidatorMode = "regex" | "ast";

export interface ValidationResult {
  passed: boolean;
  rejected: boolean;
  reasons: string[];
  mode: ValidatorMode;
}

/**
 * Dispatcher. Defaults to the AST validator — the regex validator is retained
 * only as a deliberately-weak baseline for the denylist-vs-AST comparison.
 */
export function validateGeneratedCode(
  code: string,
  mode: ValidatorMode = "ast",
): ValidationResult {
  return mode === "regex"
    ? validateGeneratedCodeRegex(code)
    : validateGeneratedCodeAst(code);
}

// ── Baseline: regex/string denylist ────────────────────────────────────────
// A naive substring denylist. Kept as the "lazy" control: it is trivially
// bypassed (`const f = fetch; f(url)`, `(0,eval)(src)`, `self["fe"+"tch"]`) and
// also fires on tokens inside strings and comments. Report its bypass rate
// against the AST validator rather than relying on it for enforcement.
export function validateGeneratedCodeRegex(code: string): ValidationResult {
  const reasons: string[] = [];

  // Exclude the Worker handler signature `async fetch(` so we only flag real
  // call sites — mirrors analyzeGeneratedCode() in agent.ts. Without this the
  // mandatory `export default { async fetch(request, env, ctx) }` shape makes
  // this rule reject every well-formed Worker.
  if (/(?<!async\s+)\bfetch\s*\(/i.test(code)) {
    reasons.push("contains fetch()");
  }
  if (/\beval\s*\(/i.test(code)) {
    reasons.push("contains eval()");
  }
  if (/\bnew\s+Function\s*\(/i.test(code)) {
    reasons.push("contains new Function()");
  }
  if (/\bimport\s*\(/i.test(code)) {
    reasons.push("contains import()");
  }
  if (/\bglobalThis\b/i.test(code)) {
    reasons.push("references globalThis");
  }
  if (/\bObject\.prototype\b/i.test(code)) {
    reasons.push("references Object.prototype");
  }

  return {
    passed: reasons.length === 0,
    rejected: reasons.length > 0,
    reasons,
    mode: "regex",
  };
}

// ── Real validator: acorn AST walk ─────────────────────────────────────────
// Structural detection over a parsed tree. Unlike the regex baseline this does
// not fire on tokens in strings/comments or on the `fetch` handler method name,
// and it catches indirections the denylist misses (member-call fetch/eval,
// `(0,eval)(...)`, dynamic import, __proto__).
//
// Known limitation: no scope/alias tracking — `const f = fetch; f()` and
// fully-computed property access (`self["fe"+"tch"]`) still pass. Closing those
// requires constant-folding + taint analysis, which is itself out of scope; the
// gap is a documented finding, not an oversight.
const GLOBAL_OBJECTS = new Set(["globalThis", "self", "window"]);

function tryParse(code: string): Node | null {
  try {
    return parse(code, { ecmaVersion: "latest", sourceType: "module" }) as Node;
  } catch {
    // Bare function bodies (the agent sometimes emits an unwrapped handler body
    // that gets wrapped later) parse as scripts with top-level return/await.
    try {
      return parse(code, {
        ecmaVersion: "latest",
        sourceType: "script",
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
      }) as Node;
    } catch {
      return null;
    }
  }
}

export function validateGeneratedCodeAst(code: string): ValidationResult {
  const ast = tryParse(code);
  if (!ast) {
    // Fail closed: code the validator cannot parse cannot be cleared.
    return {
      passed: false,
      rejected: true,
      reasons: ["unparseable: AST validator could not parse the generated code"],
      mode: "ast",
    };
  }

  const reasons = new Set<string>();

  // acorn emits ESTree nodes that acorn-walk types only loosely; `any` here is
  // the documented exception for field access on untyped AST nodes.
  walk.simple(ast, {
    CallExpression(node: any) {
      const callee = node.callee;
      if (callee.type === "Identifier") {
        if (callee.name === "fetch") reasons.add("calls fetch()");
        else if (callee.name === "eval") reasons.add("calls eval()");
        else if (callee.name === "Function") reasons.add("calls Function()");
      } else if (
        callee.type === "MemberExpression" &&
        !callee.computed &&
        callee.property.type === "Identifier" &&
        callee.object.type === "Identifier" &&
        GLOBAL_OBJECTS.has(callee.object.name) &&
        (callee.property.name === "fetch" || callee.property.name === "eval")
      ) {
        reasons.add(`calls ${callee.object.name}.${callee.property.name}()`);
      } else if (callee.type === "SequenceExpression") {
        // Indirect eval / Function: `(0, eval)(src)`.
        const last = callee.expressions[callee.expressions.length - 1];
        if (last?.type === "Identifier" && (last.name === "eval" || last.name === "Function")) {
          reasons.add(`indirect ${last.name}() via sequence expression`);
        }
      }
    },
    NewExpression(node: any) {
      if (node.callee.type === "Identifier" && node.callee.name === "Function") {
        reasons.add("uses new Function()");
      }
    },
    ImportExpression() {
      reasons.add("uses dynamic import()");
    },
    Identifier(node: any) {
      // acorn-walk only visits identifiers in reference position (non-computed
      // member property keys and method names are not visited), so this is a
      // real `globalThis` use, not a property named globalThis.
      if (node.name === "globalThis") reasons.add("references globalThis");
    },
    MemberExpression(node: any) {
      if (!node.computed && node.property.type === "Identifier") {
        if (
          node.property.name === "prototype" &&
          node.object.type === "Identifier" &&
          node.object.name === "Object"
        ) {
          reasons.add("references Object.prototype");
        }
        if (node.property.name === "__proto__") {
          reasons.add("accesses __proto__");
        }
      }
    },
  });

  const list = [...reasons];
  return {
    passed: list.length === 0,
    rejected: list.length > 0,
    reasons: list,
    mode: "ast",
  };
}
