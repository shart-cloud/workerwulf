import type { AstNode } from "../../ast/parse.js";
import { calleeMemberPath } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import {
  buildRequestTaint,
  callArgs,
  hasAuthContextHeader,
  isRequestDerived,
  literalString,
  makeFinding,
  serviceBindingNames,
} from "./_utils.js";

const INTERNAL_ORIGIN_RE = /(x-internal|x-worker|x-service|cf-worker|service-binding|service only|internal only|trusted worker)/i;
const USER_AUTH_RE = /(authorization|x-user|x-account|x-tenant|x-session|jwt|bearer|cookie|verify|authorize|authenticate|requireuser|principal)/i;

registerSource({
  id: "WF-SVC-AUTH-01",
  title: "Service binding call lacks propagated auth context",
  severity: "high",
  probe: "W-BND-03",
  family: "G",
  check(ctx) {
    const services = serviceBindingNames(ctx.config);
    if (services.size === 0) return [];
    const tainted = buildRequestTaint(ctx.source);
    const findings: Finding[] = [];

    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (!path || path[path.length - 1] !== "fetch") continue;
      const serviceName = path[path.length - 2];
      if (!serviceName || !services.has(serviceName)) continue;
      const args = callArgs(node);
      if (!isRequestDerived(args[0], tainted)) continue;
      if (hasExplicitAuthContext(args[1]) || hasExplicitAuthContext(args[0])) continue;

      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        `env.${serviceName}.fetch(...) forwards a raw request-derived Request or URL to a service binding without an explicit user/auth context header. A service binding proves the caller Worker identity, not the original user's authorization to perform the downstream action.`,
        "Propagate a signed internal auth context that names the original user, tenant, and permissions, or derive a new internal request after performing authorization in the caller. Do not forward raw attacker-controlled Requests to privileged services.",
      ));
    }
    return findings;
  },
});

registerSource({
  id: "WF-SVC-AUTH-02",
  title: "Internal route trusts service-binding origin without user auth",
  severity: "medium",
  probe: "W-BND-03",
  family: "G",
  check(ctx) {
    if (!mentionsInternalOrigin(ctx.source.ast) || hasUserAuthValidation(ctx.source.ast)) return [];
    const first = findNodes(ctx.source.ast, "Literal").find(({ node }) => {
      const value = literalString(node);
      return value !== undefined && INTERNAL_ORIGIN_RE.test(value);
    })?.node ?? ctx.source.ast;

    return [makeFinding(
      ctx.source,
      first,
      this,
      "This Worker appears to trust an internal/service-binding header or service-only route marker, but no user/auth context validation is obvious. Service binding origin confirms which Worker called, not whether the original user is authorized for the requested operation.",
      "Require a signed user/tenant/permission context on internal routes and verify it before using privileged bindings. Treat service-binding identity as caller authentication, not end-user authorization.",
    )];
  },
});

function hasExplicitAuthContext(node: AstNode | undefined): boolean {
  return hasAuthContextHeader(node);
}

function mentionsInternalOrigin(root: AstNode): boolean {
  for (const { node } of findNodes(root, "Literal")) {
    const value = literalString(node);
    if (value && INTERNAL_ORIGIN_RE.test(value)) return true;
  }
  return false;
}

function hasUserAuthValidation(root: AstNode): boolean {
  for (const { node } of findNodes(root, "CallExpression")) {
    const path = calleeMemberPath(node);
    const name = path?.[path.length - 1];
    if (name && USER_AUTH_RE.test(name)) return true;
  }
  for (const { node } of findNodes(root, "Literal")) {
    const value = literalString(node);
    if (value && USER_AUTH_RE.test(value) && !INTERNAL_ORIGIN_RE.test(value)) return true;
  }
  return false;
}
