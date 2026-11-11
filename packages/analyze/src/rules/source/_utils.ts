import { isMemberAccess, objectLiteralProperties } from "../../ast/nodes.js";
import type { AstNode, SourceFile } from "../../ast/parse.js";
import { locAt } from "../../ast/parse.js";
import { calleeMemberPath, exprName, findEnvAccess, nameLooksSecret, nodeText } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import type { Finding, Severity } from "../../engine/rule.js";
import {
  BINDING_BLAST_RADIUS,
  declaredBindings,
  secretBindingNames,
  type BindingType,
} from "../../parsers/bindings.js";
import type { WranglerConfig } from "../../parsers/wrangler.js";

const SAFE_VALUE_RE = /(allowlist|allowed|trusted|validate|verified|sanitize|normaliz|safe|canonical)/i;
const AUTH_CONTEXT_RE = /(authorization|x-auth|x-user|x-account|x-tenant|x-session|x-principal|x-internal-auth|jwt|bearer|cookie)/i;

export function callArgs(node: AstNode): AstNode[] {
  return (node["arguments"] as AstNode[] | undefined) ?? [];
}

export function propKeyName(prop: AstNode): string | undefined {
  const key = prop["key"] as AstNode | undefined;
  if (key?.type === "Identifier") return key["name"] as string;
  if (key?.type === "Literal") return String(key["value"]);
  return undefined;
}

export function propValue(prop: AstNode): AstNode | undefined {
  return prop["value"] as AstNode | undefined;
}

export function literalString(node: AstNode | undefined): string | undefined {
  if (node?.type === "Literal" && typeof node["value"] === "string") return node["value"] as string;
  return undefined;
}

export function literalNumber(node: AstNode | undefined): number | undefined {
  if (node?.type === "Literal" && typeof node["value"] === "number") return node["value"] as number;
  return undefined;
}

export function makeFinding(
  source: SourceFile,
  node: AstNode,
  rule: { id: string; title: string; severity: Severity; probe: string; family: string },
  message: string,
  remediation: string,
  severity: Severity = rule.severity,
): Finding {
  const loc = locAt(source, node.start);
  return {
    rule_id: rule.id,
    title: rule.title,
    severity,
    resource: `${source.path}:${loc.line}`,
    message,
    remediation,
    probe: rule.probe,
    family: rule.family,
    evidence: [{ type: "source", label: `${source.path}:${loc.line}`, inline: snippet(source, node) }],
  };
}

export function snippet(source: SourceFile, node: AstNode): string {
  return nodeText(source, node).replace(/\s+/g, " ").slice(0, 160);
}

export function calleeEndsWith(call: AstNode, ...parts: string[]): boolean {
  const path = calleeMemberPath(call);
  if (!path || path.length < parts.length) return false;
  return parts.every((part, i) => path[path.length - parts.length + i] === part);
}

export function isFetchCall(call: AstNode): boolean {
  const path = calleeMemberPath(call);
  return path?.length === 1 && path[0] === "fetch";
}

export function buildRequestTaint(source: SourceFile): Set<string> {
  const tainted = new Set<string>(["request", "req"]);
  let changed = true;

  while (changed) {
    changed = false;
    for (const { node } of findNodes(source.ast, "VariableDeclarator")) {
      const id = node["id"] as AstNode | undefined;
      const init = node["init"] as AstNode | undefined;
      if (id?.type !== "Identifier" || !init) continue;
      const name = id["name"] as string;
      if (!tainted.has(name) && isRequestDerived(init, tainted)) {
        tainted.add(name);
        changed = true;
      }
    }
    for (const { node } of findNodes(source.ast, "AssignmentExpression")) {
      const left = node["left"] as AstNode | undefined;
      const right = node["right"] as AstNode | undefined;
      if (left?.type !== "Identifier" || !right) continue;
      const name = left["name"] as string;
      if (!tainted.has(name) && isRequestDerived(right, tainted)) {
        tainted.add(name);
        changed = true;
      }
    }
  }

  return tainted;
}

export function isRequestDerived(node: AstNode | undefined, tainted: Set<string>): boolean {
  if (!node) return false;
  if (node.type === "Identifier") return tainted.has(node["name"] as string);
  if (node.type === "AwaitExpression") return isRequestDerived(node["argument"] as AstNode | undefined, tainted);

  if (node.type === "CallExpression") {
    if (isSafeValueCall(node)) return false;
    const path = calleeMemberPath(node) ?? [];
    const method = path[path.length - 1];
    const callee = node["callee"] as AstNode | undefined;
    if (
      ["get", "text", "json", "formData", "arrayBuffer"].includes(method ?? "") &&
      callee &&
      isRequestDerived(callee, tainted)
    ) {
      return true;
    }
  }

  if (isMemberAccess(node)) {
    const object = node["object"] as AstNode | undefined;
    if (isRequestDerived(object, tainted)) return true;
    const name = exprName(node)?.toLowerCase();
    if (name && ["headers", "url", "searchparams", "body", "pathname", "search", "href"].includes(name)) {
      return containsTaintedIdentifier(node, tainted);
    }
  }

  return containsDerivedChild(node, tainted);
}

export function hasAuthContextHeader(node: AstNode | undefined): boolean {
  if (!node) return false;
  let found = false;
  scanAst(node, (n) => {
    if (found) return;
    if (n.type === "Literal" && typeof n["value"] === "string" && AUTH_CONTEXT_RE.test(n["value"] as string)) {
      found = true;
    }
    for (const prop of objectLiteralProperties(n)) {
      const key = propKeyName(prop);
      if (key && AUTH_CONTEXT_RE.test(key)) found = true;
    }
  });
  return found;
}

export function highBlastBindingNames(config: WranglerConfig): Set<string> {
  const highTypes = new Set<BindingType>([
    "hyperdrive",
    "secret",
    "browser",
    "mtls_certificate",
    "send_email",
    "vectorize",
    "queue_producer",
    "kv_namespace",
    "r2_bucket",
    "d1_database",
    "service",
    "ai",
    "dispatch_namespace",
  ]);
  return new Set(declaredBindings(config).filter((b) => highTypes.has(b.type)).map((b) => b.name));
}

export function highBlastSummary(config: WranglerConfig): string {
  const bindings = declaredBindings(config).filter((b) => highBlastBindingNames(config).has(b.name));
  return bindings.map((b) => `${b.name}:${b.type}`).join(", ");
}

export function declaredHighBlastTypes(config: WranglerConfig): Set<BindingType> {
  return new Set(declaredBindings(config).filter((b) => highBlastBindingNames(config).has(b.name)).map((b) => b.type));
}

export function serviceBindingNames(config: WranglerConfig): Set<string> {
  return new Set(declaredBindings(config).filter((b) => b.type === "service").map((b) => b.name));
}

export function isSecretLikeExpression(
  node: AstNode,
  envNames: Set<string>,
  config: WranglerConfig,
): boolean {
  const secretNames = secretBindingNames(config);
  if (findEnvAccess(node, envNames, secretNames).length > 0) return true;
  let found = false;
  scanAst(node, (n) => {
    if (found) return;
    if (n.type === "Identifier" && nameLooksSecret(n["name"] as string)) found = true;
    if (isMemberAccess(n) && nameLooksSecret(exprName(n) ?? "")) {
      found = true;
    }
  });
  return found;
}

export function bindingTypeLabel(config: WranglerConfig, name: string): string {
  const binding = declaredBindings(config).find((b) => b.name === name);
  if (!binding) return name;
  const blast = BINDING_BLAST_RADIUS[binding.type];
  return `${name} (${binding.type}, ${blast.risk})`;
}

export function scanAst(root: AstNode, visit: (node: AstNode) => void): void {
  const scan = (value: unknown): void => {
    if (value === null || typeof value !== "object") return;
    if (Array.isArray(value)) {
      for (const item of value) scan(item);
      return;
    }
    const node = value as AstNode;
    if (typeof node.type === "string") visit(node);
    for (const key in value as Record<string, unknown>) {
      if (key === "type" || key === "start" || key === "end") continue;
      scan((value as Record<string, unknown>)[key]);
    }
  };
  scan(root);
}

function isSafeValueCall(call: AstNode): boolean {
  const path = calleeMemberPath(call);
  const name = path?.[path.length - 1];
  return Boolean(name && SAFE_VALUE_RE.test(name));
}

function containsTaintedIdentifier(node: AstNode, tainted: Set<string>): boolean {
  let found = false;
  scanAst(node, (n) => {
    if (n.type === "Identifier" && tainted.has(n["name"] as string)) found = true;
  });
  return found;
}

function containsDerivedChild(node: AstNode, tainted: Set<string>): boolean {
  let found = false;
  for (const key in node as Record<string, unknown>) {
    if (key === "type" || key === "start" || key === "end" || key === "callee") continue;
    const value = (node as Record<string, unknown>)[key];
    if (value === null || value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isAstNode(item) && isRequestDerived(item, tainted)) found = true;
      }
    } else if (isAstNode(value) && isRequestDerived(value, tainted)) {
      found = true;
    }
  }
  return found;
}

function isAstNode(value: unknown): value is AstNode {
  return typeof value === "object" && value !== null && typeof (value as { type?: unknown }).type === "string";
}
