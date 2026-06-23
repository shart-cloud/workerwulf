import type { AstNode } from "./parse.js";

export type NodeType = string;

export interface Visitor {
  /** One or more node types this visitor fires on. */
  nodeType: NodeType | NodeType[];
  /**
   * Called when a matching node is entered. `ancestors` is the parent chain,
   * nearest-last (ancestors[ancestors.length - 1] is the direct parent).
   * Return `true` to skip descending into this node's children.
   */
  enter(node: AstNode, ancestors: AstNode[]): boolean | void;
}

function isNode(value: unknown): value is AstNode {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { type?: unknown }).type === "string"
  );
}

/**
 * Depth-first walk of an oxc AST, dispatching to registered visitors by node
 * type. Generic over node shape: traverses every own property that holds a node
 * or array of nodes, so it works regardless of oxc/ESTree field naming.
 *
 * The `ancestors` array is mutated in place during traversal for efficiency;
 * visitors that need to retain it must copy.
 */
export function walk(root: AstNode, visitors: Visitor[]): void {
  // Index visitors by node type for O(1) dispatch.
  const byType = new Map<string, Visitor[]>();
  for (const v of visitors) {
    const types = Array.isArray(v.nodeType) ? v.nodeType : [v.nodeType];
    for (const t of types) {
      const list = byType.get(t);
      if (list) list.push(v);
      else byType.set(t, [v]);
    }
  }

  const ancestors: AstNode[] = [];

  function visit(node: AstNode): void {
    let skipChildren = false;
    const matched = byType.get(node.type);
    if (matched) {
      for (const v of matched) {
        if (v.enter(node, ancestors) === true) skipChildren = true;
      }
    }
    if (skipChildren) return;

    ancestors.push(node);
    for (const key in node) {
      if (key === "type" || key === "start" || key === "end") continue;
      const child = node[key];
      if (isNode(child)) {
        visit(child);
      } else if (Array.isArray(child)) {
        for (const item of child) {
          if (isNode(item)) visit(item);
        }
      }
    }
    ancestors.pop();
  }

  visit(root);
}

export interface FoundNode {
  node: AstNode;
  /** Snapshot of the ancestor chain, nearest-last. */
  ancestors: AstNode[];
}

/**
 * Collect every node of the given type(s) with a snapshot of its ancestors.
 * Convenience for source rules that match on a node type and then filter with
 * predicate helpers.
 */
export function findNodes(root: AstNode, nodeType: NodeType | NodeType[]): FoundNode[] {
  const found: FoundNode[] = [];
  walk(root, [
    {
      nodeType,
      enter(node, ancestors) {
        found.push({ node, ancestors: [...ancestors] });
      },
    },
  ]);
  return found;
}
