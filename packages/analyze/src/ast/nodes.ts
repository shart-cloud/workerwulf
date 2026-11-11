import type { AstNode } from "./parse.js";

/**
 * ESTree node predicates for oxc-parser's AST, in one place so rules don't
 * depend on node-shape details.
 *
 * Their semantics deliberately match what the rules were written against
 * (oxc 0.40's native AST):
 * - a member access is `obj.x` or `obj[expr]`, but not a private field (`this.#x`);
 * - an object property is a key/value in an object literal, not one in a
 *   destructuring pattern (ESTree calls both `Property`);
 * - a function's parameters exclude a TypeScript `this` parameter and a rest
 *   element, and unwrap `constructor(private x)` parameter properties.
 */

const isPrivate = (node: AstNode): boolean =>
  (node["property"] as AstNode | undefined)?.type === "PrivateIdentifier";

/** `obj.x` or `obj[expr]`; never `obj.#x`. */
export function isMemberAccess(node: AstNode | undefined): node is AstNode {
  return node?.type === "MemberExpression" && !isPrivate(node);
}

/** `obj.x`: non-computed, non-private. */
export function isStaticMember(node: AstNode | undefined): node is AstNode {
  return node?.type === "MemberExpression" && node["computed"] !== true && !isPrivate(node);
}

/** `obj[expr]`. */
export function isComputedMember(node: AstNode | undefined): node is AstNode {
  return node?.type === "MemberExpression" && node["computed"] === true;
}

/** Member-access node types to pass to `walk`/`findNodes`; filter with `isMemberAccess`. */
export const MEMBER_EXPRESSION = "MemberExpression";

/** Object-literal property node type; filter with `isObjectLiteralProperty`. */
export const PROPERTY = "Property";

/** A key/value inside an object literal (`{ k: v }`, `{ m() {} }`), given its parent. */
export function isObjectLiteralProperty(node: AstNode | undefined, parent: AstNode | undefined): boolean {
  return node?.type === "Property" && parent?.type === "ObjectExpression";
}

/** The properties of an object literal, excluding spreads. */
export function objectLiteralProperties(node: AstNode | undefined): AstNode[] {
  if (node?.type !== "ObjectExpression") return [];
  return ((node["properties"] as AstNode[] | undefined) ?? []).filter((p) => p.type === "Property");
}

/**
 * The declared parameter patterns of a function, in order: Identifier,
 * ObjectPattern, ArrayPattern or AssignmentPattern.
 */
export function functionParams(fn: AstNode): AstNode[] {
  const params = (fn["params"] as AstNode[] | undefined) ?? [];
  const out: AstNode[] = [];
  for (const param of params) {
    if (param.type === "RestElement") continue;
    if (param.type === "Identifier" && param["name"] === "this") continue; // TS `this` parameter
    if (param.type === "TSParameterProperty") {
      const inner = param["parameter"] as AstNode | undefined;
      if (inner) out.push(inner);
      continue;
    }
    out.push(param);
  }
  return out;
}
