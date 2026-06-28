import type { AstNode } from "../../ast/parse.js";
import { calleeMemberPath, isConstructOf } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import {
  buildRequestTaint,
  callArgs,
  calleeEndsWith,
  declaredHighBlastTypes,
  highBlastSummary,
  isFetchCall,
  isRequestDerived,
  literalNumber,
  literalString,
  makeFinding,
  propKeyName,
  propValue,
} from "./_utils.js";

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

registerSource({
  id: "WF-REQ-SSRF-01",
  title: "Request-derived URL passed to fetch()",
  severity: "high",
  probe: "W-CAP-05",
  family: "B",
  check(ctx) {
    const tainted = buildRequestTaint(ctx.source);
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isFetchCall(node)) continue;
      const target = callArgs(node)[0];
      if (!isRequestDerived(target, tainted)) continue;
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        "fetch() is called with a URL or Request derived from inbound request data. In Workers this creates an SSRF sink that can reach internal services, metadata-like endpoints, or authenticated upstreams available to the Worker.",
        "Route outbound fetches through a static allowlist of origins and paths. Reject or canonicalize user-controlled URLs before fetch(), and never fetch request.url or raw search-parameter targets directly.",
      ));
    }
    return findings;
  },
});

registerSource({
  id: "WF-REQ-REDIR-01",
  title: "Request-derived open redirect",
  severity: "medium",
  probe: "W-RUN-*",
  family: "B",
  check(ctx) {
    const tainted = buildRequestTaint(ctx.source);
    const findings: Finding[] = [];

    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!calleeEndsWith(node, "Response", "redirect")) continue;
      const target = callArgs(node)[0];
      if (!isRequestDerived(target, tainted)) continue;
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        "Response.redirect() uses a request-derived destination. Attackers can turn the Worker route into an open redirect for phishing, OAuth token theft, or redirect-chain abuse.",
        "Redirect only to a fixed set of same-origin or explicitly allowlisted destinations. Validate and canonicalize the destination before calling Response.redirect().",
      ));
    }

    for (const { node } of findNodes(ctx.source.ast, "NewExpression")) {
      if (!isConstructOf(node, "Response")) continue;
      const options = callArgs(node)[1];
      if (!responseOptionsHasRedirectLocation(options, tainted)) continue;
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        "new Response(..., { status: 30x, headers: { Location: ... } }) sets a redirect Location from request-derived input. This is an open redirect if the value is not constrained to trusted destinations.",
        "Use an allowlist for redirect targets and set Location only after canonical validation. Prefer relative same-origin paths when possible.",
      ));
    }
    return findings;
  },
});

registerSource({
  id: "WF-REQ-CORS-01",
  title: "Wildcard CORS on Worker route",
  severity: "medium",
  probe: "W-CAP-*",
  family: "G",
  check(ctx) {
    const findings: Finding[] = [];
    const sensitiveTypes = declaredHighBlastTypes(ctx.config);
    const hasSensitiveBindings = sensitiveTypes.size > 0;
    const severity = hasSensitiveBindings ? "high" : "low";
    const bindingText = hasSensitiveBindings ? ` Declared sensitive bindings: ${highBlastSummary(ctx.config)}.` : "";

    for (const { node } of findNodes(ctx.source.ast, "ObjectProperty")) {
      const key = propKeyName(node)?.toLowerCase();
      if (key !== "access-control-allow-origin") continue;
      if (literalString(propValue(node)) !== "*") continue;
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        `The Worker returns Access-Control-Allow-Origin: *.${bindingText} Browser clients on any origin can read responses from this route if credentials or tokens are otherwise available to the request path.`,
        "Return CORS origins from an explicit allowlist and vary by Origin. Avoid wildcard CORS on routes that can reach secrets, databases, storage, AI, services, queues, browser rendering, mTLS, or email bindings.",
        severity,
      ));
    }

    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (path?.[path.length - 1] !== "set") continue;
      const args = callArgs(node);
      if (literalString(args[0])?.toLowerCase() !== "access-control-allow-origin") continue;
      if (literalString(args[1]) !== "*") continue;
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        `headers.set("Access-Control-Allow-Origin", "*") enables wildcard CORS.${bindingText} This can expose binding-backed responses to arbitrary web origins.`,
        "Set Access-Control-Allow-Origin only after matching Origin against an allowlist, and do not use wildcard CORS on privileged Worker routes.",
        severity,
      ));
    }
    return findings;
  },
});

registerSource({
  id: "WF-REQ-HDR-01",
  title: "Request-derived value copied into response headers",
  severity: "medium",
  probe: "W-RUN-*",
  family: "B",
  check(ctx) {
    const tainted = buildRequestTaint(ctx.source);
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "NewExpression")) {
      if (isConstructOf(node, "Headers") && isRequestDerived(callArgs(node)[0], tainted)) {
        findings.push(makeFinding(
          ctx.source,
          node,
          this,
          "new Headers(...) is initialized from request-derived headers. Copying request headers wholesale into a response can reflect attacker-controlled header values into security-sensitive response metadata.",
          "Construct response headers explicitly. Copy only known-safe header names and validate values before setting them on the response.",
        ));
      }
      if (isConstructOf(node, "Response") && responseOptionsHasRequestHeaders(callArgs(node)[1], tainted)) {
        findings.push(makeFinding(
          ctx.source,
          node,
          this,
          "Response options use request-derived headers. This can reflect attacker-controlled values into the response header surface.",
          "Build response headers from a fixed allowlist and avoid passing request.headers or user-controlled header values directly to new Response().",
        ));
      }
    }

    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (path?.[path.length - 1] !== "set") continue;
      const args = callArgs(node);
      if (!isRequestDerived(args[1], tainted)) continue;
      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        "A response Headers.set(...) call writes a request-derived value into a response header. Header reflection can enable cache poisoning, response-splitting-adjacent bugs, and policy-header bypasses.",
        "Set response headers from fixed server-side values or validate request-derived values against a narrow allowlist before writing them.",
      ));
    }
    return findings;
  },
});

function responseOptionsHasRedirectLocation(options: AstNode | undefined, tainted: Set<string>): boolean {
  if (options?.type !== "ObjectExpression") return false;
  const properties = (options["properties"] as AstNode[] | undefined) ?? [];
  let hasRedirectStatus = false;
  let hasTaintedLocation = false;
  for (const prop of properties) {
    if (prop.type !== "ObjectProperty") continue;
    const key = propKeyName(prop)?.toLowerCase();
    const value = propValue(prop);
    if (key === "status" && REDIRECT_STATUSES.has(literalNumber(value) ?? 0)) hasRedirectStatus = true;
    if (key === "headers") hasTaintedLocation = headersObjectHasTaintedLocation(value, tainted);
  }
  return hasRedirectStatus && hasTaintedLocation;
}

function headersObjectHasTaintedLocation(headers: AstNode | undefined, tainted: Set<string>): boolean {
  if (headers?.type !== "ObjectExpression") return false;
  const properties = (headers["properties"] as AstNode[] | undefined) ?? [];
  return properties.some(
    (prop) => prop.type === "ObjectProperty" && propKeyName(prop)?.toLowerCase() === "location" && isRequestDerived(propValue(prop), tainted),
  );
}

function responseOptionsHasRequestHeaders(options: AstNode | undefined, tainted: Set<string>): boolean {
  if (options?.type !== "ObjectExpression") return false;
  const properties = (options["properties"] as AstNode[] | undefined) ?? [];
  return properties.some(
    (prop) => prop.type === "ObjectProperty" && propKeyName(prop)?.toLowerCase() === "headers" && isRequestDerived(propValue(prop), tainted),
  );
}
