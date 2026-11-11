import { functionParams, isObjectLiteralProperty, PROPERTY } from "./nodes.js";
import type { AstNode } from "./parse.js";
import { findNodes } from "./walk.js";

export type WorkerHandlerKind = "fetch" | "scheduled" | "queue" | "email" | "tail" | "alarm";

const HANDLER_KEYS = new Set<WorkerHandlerKind>([
  "fetch",
  "scheduled",
  "queue",
  "email",
  "tail",
  "alarm",
]);

const FUNCTION_TYPES = new Set([
  "FunctionDeclaration",
  "FunctionExpression",
  "ArrowFunctionExpression",
]);

/** Return the Worker handler that encloses a node, if it is structurally obvious. */
export function enclosingWorkerHandler(ancestors: AstNode[]): WorkerHandlerKind | undefined {
  return enclosingWorkerHandlerInfo(ancestors)?.kind;
}

/** Return the enclosing Worker handler and function node, if structurally obvious. */
export function enclosingWorkerHandlerInfo(
  ancestors: AstNode[],
): { kind: WorkerHandlerKind; fn: AstNode } | undefined {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const fn = ancestors[i];
    if (!fn || !FUNCTION_TYPES.has(fn.type)) continue;
    const parent = ancestors[i - 1];
    const grandparent = ancestors[i - 2];

    const parentKey = isObjectLiteralProperty(parent, grandparent) ? propertyKeyName(parent!) : undefined;
    if (parentKey && HANDLER_KEYS.has(parentKey as WorkerHandlerKind)) {
      return { kind: parentKey as WorkerHandlerKind, fn };
    }

    // `export default async function fetch(...) {}` is uncommon for module workers,
    // but treat a default-exported function as fetch for conservative source checks.
    if (parent?.type === "ExportDefaultDeclaration" || grandparent?.type === "ExportDefaultDeclaration") {
      return { kind: "fetch", fn };
    }
  }
  return undefined;
}

/** Formal parameter names for a function-like node. */
export function functionParamNames(fn: AstNode): string[] {
  return functionParams(fn)
    .filter((p) => p.type === "Identifier")
    .map((p) => p["name"] as string);
}

/** All structurally-declared Worker handlers in a source tree. */
export function findWorkerHandlers(root: AstNode): { kind: WorkerHandlerKind; fn: AstNode }[] {
  const handlers: { kind: WorkerHandlerKind; fn: AstNode }[] = [];
  for (const { node, ancestors } of findNodes(root, PROPERTY)) {
    if (!isObjectLiteralProperty(node, ancestors[ancestors.length - 1])) continue;
    const key = propertyKeyName(node);
    if (!key || !HANDLER_KEYS.has(key as WorkerHandlerKind)) continue;
    const value = node["value"] as AstNode | undefined;
    if (value && FUNCTION_TYPES.has(value.type)) handlers.push({ kind: key as WorkerHandlerKind, fn: value });
  }
  return handlers;
}

function propertyKeyName(prop: AstNode): string | undefined {
  const key = prop["key"] as AstNode | undefined;
  if (key?.type === "Identifier") return key["name"] as string;
  if (key?.type === "Literal") return String(key["value"]);
  return undefined;
}
