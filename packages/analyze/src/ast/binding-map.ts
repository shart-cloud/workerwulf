import { functionParams, isMemberAccess, isObjectLiteralProperty, isStaticMember, MEMBER_EXPRESSION } from "./nodes.js";
import type { AstNode, SourceFile, SourceLocation } from "./parse.js";
import { locAt } from "./parse.js";
import { walk } from "./walk.js";

export interface BindingRef {
  /** Binding name, e.g. "MY_KV". */
  name: string;
  accessType: "dot" | "bracket" | "destructure";
  loc: SourceLocation;
  /** Ancestor node types, nearest-last, for context checks. */
  ancestors: string[];
  /** If this ref is the receiver of a method call (env.X.get()), the method name. */
  methodCall?: string;
}

export interface BindingMap {
  /** All env.X references found in source. */
  refs: BindingRef[];
  /** Deduplicated set of binding names referenced. */
  used: Set<string>;
  /** Identifier names that resolve to the env parameter (usually just "env"). */
  envNames: Set<string>;
  /** Whether the env parameter was destructured (complicates least-priv analysis). */
  envDestructured: boolean;
}

const HANDLER_KEYS = new Set([
  "fetch",
  "scheduled",
  "queue",
  "email",
  "tail",
  "trace",
  "alarm",
]);

const FUNCTION_TYPES = new Set([
  "FunctionDeclaration",
  "FunctionExpression",
  "ArrowFunctionExpression",
]);

/** Return the pattern node of the `index`-th formal parameter, if present. */
function paramPattern(fn: AstNode, index: number): AstNode | undefined {
  return functionParams(fn)[index];
}

/** Collect binding names declared in an ObjectPattern (destructuring). */
function objectPatternNames(pattern: AstNode): string[] {
  const names: string[] = [];
  const properties = (pattern["properties"] as AstNode[] | undefined) ?? [];
  for (const prop of properties) {
    // ESTree: Property { key, value, shorthand }; a RestElement has no key and is skipped.
    const key = prop["key"] as AstNode | undefined;
    if (key?.type === "Identifier") names.push(key["name"] as string);
    else if (key?.type === "Literal") names.push(String(key["value"]));
  }
  return names;
}

/**
 * Build the binding map for a Worker source file.
 *
 * Identifies the `env` parameter from Workers handler signatures
 * (fetch/scheduled/queue/email/... as the 2nd arg, or `export default` function),
 * then collects every `env.X`, `env["X"]`, and `const { X } = env` reference.
 *
 * Limitations (documented honestly per PRD §12.1): handles dot/bracket access and
 * simple destructuring, but cannot follow bindings through arbitrary aliasing or
 * indirection. False negatives are possible on bundled/minified code.
 */
export function buildBindingMap(source: SourceFile): BindingMap {
  const envNames = new Set<string>();
  const destructuredNames = new Set<string>();
  let envDestructured = false;

  // Pass 1 — discover env parameter name(s) from handler signatures.
  walk(source.ast, [
    {
      nodeType: [...FUNCTION_TYPES],
      enter(fn, ancestors) {
        const parent = ancestors[ancestors.length - 1];
        const grandparent = ancestors[ancestors.length - 2];
        const isHandler =
          // { fetch(req, env, ctx) {} } or fetch: (req, env) => {}
          (isObjectLiteralProperty(parent, grandparent) &&
            keyName(parent!) !== undefined &&
            HANDLER_KEYS.has(keyName(parent!)!)) ||
          // export default async (req, env, ctx) => {}
          parent?.type === "ExportDefaultDeclaration" ||
          grandparent?.type === "ExportDefaultDeclaration";

        const second = paramPattern(fn, 1);
        if (!second) return;
        if (second.type === "Identifier") {
          // Treat as env if it's a recognized handler OR conventionally named "env".
          if (isHandler || second["name"] === "env") {
            envNames.add(second["name"] as string);
          }
        } else if (second.type === "ObjectPattern" && isHandler) {
          envDestructured = true;
          for (const n of objectPatternNames(second)) destructuredNames.add(n);
        }
      },
    },
  ]);

  if (envNames.size === 0 && destructuredNames.size === 0) {
    // Fallback: assume the conventional name so generic code is still analyzed.
    envNames.add("env");
  }

  const refs: BindingRef[] = [];
  const used = new Set<string>(destructuredNames);

  for (const n of destructuredNames) {
    refs.push({
      name: n,
      accessType: "destructure",
      loc: locAt(source, 0),
      ancestors: [],
    });
  }

  // Pass 2 — collect env.X / env["X"] / const { X } = env references.
  walk(source.ast, [
    {
      nodeType: MEMBER_EXPRESSION,
      enter(node, ancestors) {
        if (!isMemberAccess(node)) return;
        const object = node["object"] as AstNode | undefined;
        if (object?.type !== "Identifier") return;
        if (!envNames.has(object["name"] as string)) return;

        let name: string | undefined;
        let accessType: BindingRef["accessType"];
        if (isStaticMember(node)) {
          const property = node["property"] as AstNode | undefined;
          if (property?.type !== "Identifier") return;
          name = property["name"] as string;
          accessType = "dot";
        } else {
          const expr = node["property"] as AstNode | undefined;
          if (expr?.type !== "Literal" || typeof expr["value"] !== "string") return;
          name = expr["value"] as string;
          accessType = "bracket";
        }
        if (!name) return;

        refs.push({
          name,
          accessType,
          loc: locAt(source, node.start),
          ancestors: ancestors.map((a) => a.type),
          methodCall: detectMethodCall(node, ancestors),
        });
        used.add(name);
      },
    },
    {
      // const { X, Y } = env;
      nodeType: "VariableDeclarator",
      enter(node) {
        const id = node["id"] as AstNode | undefined;
        const init = node["init"] as AstNode | undefined;
        if (id?.type !== "ObjectPattern") return;
        if (init?.type !== "Identifier") return;
        if (!envNames.has(init["name"] as string)) return;
        envDestructured = true;
        for (const n of objectPatternNames(id)) {
          refs.push({
            name: n,
            accessType: "destructure",
            loc: locAt(source, node.start),
            ancestors: [],
          });
          used.add(n);
        }
      },
    },
  ]);

  return { refs, used, envNames, envDestructured };
}

function keyName(prop: AstNode): string | undefined {
  const key = prop["key"] as AstNode | undefined;
  if (key?.type === "Identifier") return key["name"] as string;
  if (key?.type === "Literal") return String(key["value"]);
  return undefined;
}

/**
 * If `member` (e.g. env.KV) is the receiver of a method call (env.KV.get(...)),
 * return the method name ("get"). The parent in the AST is the outer
 * non-computed `MemberExpression` whose property is the method, and its parent is the
 * CallExpression.
 */
function detectMethodCall(member: AstNode, ancestors: AstNode[]): string | undefined {
  const parent = ancestors[ancestors.length - 1];
  const grandparent = ancestors[ancestors.length - 2];
  if (
    isStaticMember(parent) &&
    parent["object"] === member &&
    grandparent?.type === "CallExpression" &&
    grandparent["callee"] === parent
  ) {
    const method = parent["property"] as AstNode | undefined;
    if (method?.type === "Identifier") return method["name"] as string;
  }
  return undefined;
}
