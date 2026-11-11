import { isComputedMember, isMemberAccess, isStaticMember } from "./nodes.js";
import type { AstNode, SourceFile } from "./parse.js";

const FUNCTION_TYPES = new Set([
  "FunctionDeclaration",
  "FunctionExpression",
  "ArrowFunctionExpression",
]);

const LOOP_TYPES = new Set([
  "ForStatement",
  "ForInStatement",
  "ForOfStatement",
  "WhileStatement",
  "DoWhileStatement",
]);

const SECRET_NAME_RE = /(secret|token|password|passwd|api[_-]?key|apikey|auth|credential|private[_-]?key)/i;

/**
 * High-entropy / vendor-prefixed secret literal patterns. Conservative on
 * purpose — meant to catch obvious hardcoded credentials, not every long
 * string. Family A (WF-SEC-01).
 */
const SECRET_LITERAL_RES: RegExp[] = [
  /\bsk_live_[A-Za-z0-9]{8,}/, // Stripe-style live secret
  /\bsk_test_[A-Za-z0-9]{8,}/,
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key id
  /\bghp_[A-Za-z0-9]{20,}/, // GitHub PAT
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/, // Slack token
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, // JWT
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, // PEM private key
  /\b[0-9a-f]{40,}\b/, // long lowercase hex blob (>=40, e.g. CF API token)
];

/** Get the identifier name a CallExpression's callee resolves to, if simple. */
function calleeName(node: AstNode): string | undefined {
  const callee = node["callee"] as AstNode | undefined;
  if (!callee) return undefined;
  if (callee.type === "Identifier") return callee["name"] as string;
  return undefined;
}

/** For a member-expression callee, return "object.property" (e.g. "console.log"). */
function memberCalleeName(node: AstNode): string | undefined {
  const callee = node["callee"] as AstNode | undefined;
  if (!isStaticMember(callee)) return undefined;
  const object = callee["object"] as AstNode | undefined;
  const property = callee["property"] as AstNode | undefined;
  if (object?.type !== "Identifier" || property?.type !== "Identifier") {
    return undefined;
  }
  return `${object["name"] as string}.${property["name"] as string}`;
}

/** True if `node` is a call to a bare named function, e.g. isCallTo(n, "eval"). */
export function isCallTo(node: AstNode, name: string): boolean {
  if (node.type !== "CallExpression") return false;
  if (name.includes(".")) return memberCalleeName(node) === name;
  return calleeName(node) === name;
}

/** True if `node` is `new X(...)` for the given constructor name. */
export function isConstructOf(node: AstNode, name: string): boolean {
  if (node.type !== "NewExpression") return false;
  const callee = node["callee"] as AstNode | undefined;
  return callee?.type === "Identifier" && callee["name"] === name;
}

/** True if no enclosing function — i.e. the node sits at module scope. */
export function isModuleScope(ancestors: AstNode[]): boolean {
  return !ancestors.some((a) => FUNCTION_TYPES.has(a.type));
}

/** True if the node is inside a CatchClause body. */
export function isInCatchBlock(ancestors: AstNode[]): boolean {
  return ancestors.some((a) => a.type === "CatchClause");
}

/** True if the node is inside a loop body. */
export function isInLoop(ancestors: AstNode[]): boolean {
  return ancestors.some((a) => LOOP_TYPES.has(a.type));
}

/**
 * Extract a static string value from a node if it's a string Literal or a
 * template literal with no interpolated expressions. Otherwise undefined.
 */
export function staticStringValue(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "Literal" && typeof node["value"] === "string") {
    return node["value"] as string;
  }
  if (node.type === "TemplateLiteral") {
    const expressions = (node["expressions"] as AstNode[] | undefined) ?? [];
    if (expressions.length > 0) return undefined;
    const quasis = (node["quasis"] as AstNode[] | undefined) ?? [];
    return quasis
      .map((q) => {
        const cooked = (q["value"] as { cooked?: string } | undefined)?.cooked;
        return cooked ?? "";
      })
      .join("");
  }
  return undefined;
}

/** True if a string literal node looks like a hardcoded secret/token. */
export function looksLikeSecret(node: AstNode): boolean {
  const value = staticStringValue(node);
  if (!value || value.length < 8) return false;
  return SECRET_LITERAL_RES.some((re) => re.test(value));
}

/** True if an identifier/member name looks like it names a secret. */
export function nameLooksSecret(name: string): boolean {
  return SECRET_NAME_RE.test(name);
}

/**
 * True if a node looks like a "success" verdict value: a `new Response(...)`,
 * or an object literal carrying success-shaped properties
 * (decision:"allow", safe:true, blocked:false, allowed:true, status:200).
 * Static twin of the F-001 fail-open pattern (WF-FAIL-01).
 */
export function isSuccessValue(node: AstNode | undefined): boolean {
  if (!node) return false;
  if (node.type === "NewExpression" && isConstructOf(node, "Response")) {
    // new Response(...) with no explicit error status reads as success.
    return true;
  }
  if (node.type === "ObjectExpression") {
    const props = (node["properties"] as AstNode[] | undefined) ?? [];
    for (const prop of props) {
      if (prop.type !== "Property") continue;
      const key = prop["key"] as AstNode | undefined;
      const keyName =
        key?.type === "Identifier"
          ? (key["name"] as string)
          : key?.type === "Literal"
            ? String(key["value"])
            : undefined;
      if (!keyName) continue;
      const value = prop["value"] as AstNode | undefined;
      const k = keyName.toLowerCase();
      const v = value?.type === "Literal" ? value["value"] : undefined;
      if ((k === "decision" || k === "verdict" || k === "action") && v === "allow") return true;
      if ((k === "safe" || k === "allowed" || k === "ok" || k === "success") && v === true) return true;
      if (k === "blocked" && v === false) return true;
      if (k === "status" && v === 200) return true;
    }
  }
  return false;
}

/** Raw source text spanned by a node. */
export function nodeText(source: SourceFile, node: AstNode): string {
  return source.text.slice(node.start, node.end);
}

/** Name an expression resolves to: identifier name, or member property name. */
export function exprName(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "Identifier") return node["name"] as string;
  if (isStaticMember(node)) {
    const property = node["property"] as AstNode | undefined;
    if (property?.type === "Identifier") return property["name"] as string;
  }
  if (isComputedMember(node)) {
    const expr = node["property"] as AstNode | undefined;
    if (expr?.type === "Literal" && typeof expr["value"] === "string") {
      return expr["value"] as string;
    }
  }
  return undefined;
}

const EQUALITY_OPS = new Set(["===", "==", "!==", "!="]);

/**
 * True if `node` is an equality comparison where one operand names a secret
 * (per `isSecret`, defaulting to the name heuristic). Such comparisons short-
 * circuit and leak length/prefix timing — secrets must use a constant-time
 * compare (crypto.subtle.timingSafeEqual). A timingSafeEqual call is structurally
 * a CallExpression, so its presence means there is no BinaryExpression to match.
 */
export function isTimingUnsafeComparison(
  node: AstNode,
  isSecret: (name: string) => boolean = nameLooksSecret,
): boolean {
  if (node.type !== "BinaryExpression") return false;
  if (!EQUALITY_OPS.has(node["operator"] as string)) return false;
  const left = exprName(node["left"] as AstNode | undefined);
  const right = exprName(node["right"] as AstNode | undefined);
  return (
    (left !== undefined && isSecret(left)) ||
    (right !== undefined && isSecret(right))
  );
}

const REQUEST_IDENTS = new Set([
  "request",
  "req",
  "url",
  "searchparams",
  "body",
  "input",
  "query",
  "userinput",
  "params",
  "payload",
]);
const REQUEST_MEMBERS = new Set([
  "searchparams",
  "pathname",
  "search",
  "href",
  "text",
  "json",
  "formdata",
  "arraybuffer",
]);

/**
 * Heuristic taint check: does the subtree reference request-derived input?
 * Looks for request-ish identifiers (request, req, url, body, params, ...) and
 * member accesses (.searchParams, .pathname, .text(), .json(), ...). Conservative
 * and structural — cannot prove dataflow, so false positives/negatives are
 * possible (documented per PRD §12.1).
 */
export function referencesRequestInput(node: AstNode): boolean {
  let found = false;
  const scan = (value: unknown): void => {
    if (found || value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) scan(item);
      return;
    }
    const n = value as AstNode;
    if (typeof n.type === "string") {
      if (n.type === "Identifier" && REQUEST_IDENTS.has((n["name"] as string).toLowerCase())) {
        found = true;
        return;
      }
      if (isStaticMember(n)) {
        const property = n["property"] as AstNode | undefined;
        if (property?.type === "Identifier" && REQUEST_MEMBERS.has((property["name"] as string).toLowerCase())) {
          found = true;
          return;
        }
      }
    }
    for (const key in value as Record<string, unknown>) {
      if (key === "type" || key === "start" || key === "end") continue;
      scan((value as Record<string, unknown>)[key]);
    }
  };
  scan(node);
  return found;
}

/**
 * Dotted path of a CallExpression's callee, e.g. `puppeteer.launch()` →
 * ["puppeteer", "launch"], `sql.exec()` → ["sql", "exec"]. Stops at the first
 * non-member/identifier link (this/calls), so `this.sql.exec()` → ["sql", "exec"].
 */
export function calleeMemberPath(call: AstNode): string[] | undefined {
  if (call.type !== "CallExpression") return undefined;
  const path: string[] = [];
  let cur = call["callee"] as AstNode | undefined;
  while (cur) {
    if (cur.type === "Identifier") {
      path.unshift(cur["name"] as string);
      break;
    }
    if (isStaticMember(cur)) {
      const property = cur["property"] as AstNode | undefined;
      if (property?.type === "Identifier") path.unshift(property["name"] as string);
      cur = cur["object"] as AstNode | undefined;
    } else {
      break;
    }
  }
  return path.length > 0 ? path : undefined;
}

/** Final method name of a member-callee call (`a.b.c()` → "c"). */
export function calleeMethodName(call: AstNode): string | undefined {
  const path = calleeMemberPath(call);
  return path?.[path.length - 1];
}

/** True if a template literal contains interpolated `${...}` expressions. */
export function templateHasExpressions(node: AstNode | undefined): boolean {
  return (
    node?.type === "TemplateLiteral" &&
    ((node["expressions"] as AstNode[] | undefined)?.length ?? 0) > 0
  );
}

/** True if `node` is a string-building `+` concatenation. */
export function isStringConcat(node: AstNode | undefined): boolean {
  return node?.type === "BinaryExpression" && node["operator"] === "+";
}

/**
 * Find `env.<binding>` / `env["binding"]` member accesses inside a subtree.
 * `envNames` is the set of identifiers resolving to the env param. When `only`
 * is given, restricts to those binding names. Returns the matching member nodes.
 */
export function findEnvAccess(
  root: AstNode,
  envNames: Set<string>,
  only?: Set<string>,
): { node: AstNode; binding: string }[] {
  const out: { node: AstNode; binding: string }[] = [];
  const scan = (value: unknown): void => {
    if (value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) scan(item);
      return;
    }
    const n = value as AstNode;
    if (isMemberAccess(n)) {
      const object = n["object"] as AstNode | undefined;
      if (object?.type === "Identifier" && envNames.has(object["name"] as string)) {
        const binding = exprName(n);
        if (binding && (!only || only.has(binding))) out.push({ node: n, binding });
      }
    }
    for (const key in value as Record<string, unknown>) {
      if (key === "type" || key === "start" || key === "end") continue;
      scan((value as Record<string, unknown>)[key]);
    }
  };
  scan(root);
  return out;
}

const MUTABLE_CONTAINER_CTORS = new Set(["Map", "Set", "WeakMap", "WeakSet", "Array", "Object"]);

/** True if `node` is a mutable container: [], {}, or new Map/Set/WeakMap/WeakSet/.... */
export function isMutableContainer(node: AstNode | undefined): boolean {
  if (!node) return false;
  if (node.type === "ArrayExpression" || node.type === "ObjectExpression") return true;
  if (node.type === "NewExpression") {
    const callee = node["callee"] as AstNode | undefined;
    return callee?.type === "Identifier" && MUTABLE_CONTAINER_CTORS.has(callee["name"] as string);
  }
  return false;
}
