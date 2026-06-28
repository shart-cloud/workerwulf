import type { AstNode } from "../../ast/parse.js";
import { calleeMemberPath, isConstructOf } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import {
  buildRequestTaint,
  callArgs,
  isRequestDerived,
  isSecretLikeExpression,
  makeFinding,
} from "./_utils.js";

registerSource({
  id: "WF-CACHE-POISON-01",
  title: "Request-derived Cache API key",
  severity: "high",
  probe: "W-RUN-*",
  family: "C",
  check(ctx) {
    const tainted = buildRequestTaint(ctx.source);
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isCachePutCall(node)) continue;
      const key = callArgs(node)[0];
      if (!isRequestDerived(key, tainted)) continue;
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        "Cache API put() uses a cache key derived from inbound request data. Attackers can steer cache entries, poison shared cache state, or create unbounded cache cardinality.",
        "Use a server-controlled cache key. Normalize and allowlist any request components included in cache keys, and never use raw request URLs, headers, bodies, or search parameters directly.",
      ));
    }
    return findings;
  },
});

registerSource({
  id: "WF-CACHE-POISON-02",
  title: "Request-derived response body written to Cache API",
  severity: "high",
  probe: "W-RUN-*",
  family: "C",
  check(ctx) {
    const tainted = buildRequestTaint(ctx.source);
    const derivedResponses = responseVariables(ctx.source.ast, (body) => isRequestDerived(body, tainted));
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isCachePutCall(node)) continue;
      const response = callArgs(node)[1];
      if (!response || !responseBodyMatches(response, derivedResponses, (body) => isRequestDerived(body, tainted))) continue;
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        "Cache API put() stores a Response body derived from request input. This can turn attacker-controlled content into shared cached content served to later users.",
        "Only cache responses generated from trusted upstreams or server-side state. Do not cache bodies built from request text, JSON, form data, headers, or search parameters unless they are fully validated and scoped per user.",
      ));
    }
    return findings;
  },
});

registerSource({
  id: "WF-CACHE-SENSITIVE-01",
  title: "Secret-like value written to Cache API",
  severity: "high",
  probe: "W-CAP-02",
  family: "A",
  check(ctx) {
    const sensitiveResponses = responseVariables(ctx.source.ast, (body) =>
      isSecretLikeExpression(body, ctx.bindingMap.envNames, ctx.config),
    );
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isCachePutCall(node)) continue;
      const response = callArgs(node)[1];
      if (!response || !responseBodyMatches(response, sensitiveResponses, (body) => isSecretLikeExpression(body, ctx.bindingMap.envNames, ctx.config))) {
        continue;
      }
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        "Cache API put() stores a Response that includes a secret-like value or secret-classified binding. Cache contents can be replayed to later callers and may outlive the request that produced them.",
        "Never put secrets, tokens, credentials, Hyperdrive connection strings, or secret-looking variables into the Cache API. Redact sensitive fields before constructing cacheable responses.",
      ));
    }
    return findings;
  },
});

function isCachePutCall(call: AstNode): boolean {
  const path = calleeMemberPath(call);
  if (!path || path[path.length - 1] !== "put") return false;
  const receiver = path.slice(0, -1).join(".").toLowerCase();
  return receiver === "cache" || receiver === "caches.default" || receiver.endsWith(".cache");
}

function responseVariables(root: AstNode, predicate: (body: AstNode) => boolean): Set<string> {
  const names = new Set<string>();
  for (const { node } of findNodes(root, "VariableDeclarator")) {
    const id = node["id"] as AstNode | undefined;
    const init = node["init"] as AstNode | undefined;
    if (id?.type !== "Identifier" || !init) continue;
    if (newResponseBodyMatches(init, predicate)) names.add(id["name"] as string);
  }
  return names;
}

function responseBodyMatches(response: AstNode, names: Set<string>, predicate: (body: AstNode) => boolean): boolean {
  if (response.type === "Identifier" && names.has(response["name"] as string)) return true;
  return newResponseBodyMatches(response, predicate);
}

function newResponseBodyMatches(node: AstNode, predicate: (body: AstNode) => boolean): boolean {
  if (!isConstructOf(node, "Response")) return false;
  const body = callArgs(node)[0];
  return Boolean(body && predicate(body));
}
