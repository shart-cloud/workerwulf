import type { AstNode } from "../../ast/parse.js";
import { enclosingWorkerHandler } from "../../ast/handlers.js";
import { calleeMemberPath, exprName, nameLooksSecret } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import { bindingTypeLabel, highBlastBindingNames, literalString, makeFinding } from "./_utils.js";

const NON_HTTP_HANDLERS = new Set(["scheduled", "queue", "email", "tail"]);
const GUARD_RE = /(auth|authoriz|verify|validat|allow|tenant|principal|signature|hmac|jwt|session|permission|policy)/i;

registerSource({
  id: "WF-HANDLER-PRIV-01",
  title: "Privileged binding used from non-fetch Worker handler",
  severity: "medium",
  probe: "W-BND-01",
  family: "G",
  check(ctx) {
    const highBlast = highBlastBindingNames(ctx.config);
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const { node, ancestors } of findNodes(ctx.source.ast, ["StaticMemberExpression", "ComputedMemberExpression"])) {
      const object = node["object"] as AstNode | undefined;
      if (object?.type !== "Identifier" || !ctx.bindingMap.envNames.has(object["name"] as string)) continue;
      const binding = exprName(node);
      if (!binding) continue;
      if (!highBlast.has(binding) && !nameLooksSecret(binding)) continue;

      const handler = enclosingWorkerHandler(ancestors);
      if (!handler || !NON_HTTP_HANDLERS.has(handler)) continue;
      if (handler !== "scheduled" && handlerHasObviousGuard(ancestors)) continue;

      const key = `${handler}:${binding}:${node.start}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const trustBoundary = handler === "scheduled"
        ? "scheduled handlers run without an inbound user request but retain full binding authority"
        : `${handler} handlers are triggered outside the HTTP request-auth boundary; service, queue, email, or tail delivery proves event source context, not end-user authorization`;

      findings.push(makeFinding(
        ctx.source,
        node,
        this,
        `Privileged binding ${bindingTypeLabel(ctx.config, binding)} is used from the ${handler} handler with no obvious guard or validation. ${trustBoundary}.`,
        "Move privileged operations behind explicit authorization or event validation. Scope bindings per handler where possible, and validate queue/email/tail payload authority before using data, storage, service, AI, browser, mTLS, or secret-capable bindings.",
      ));
    }
    return findings;
  },
});

function handlerHasObviousGuard(ancestors: AstNode[]): boolean {
  const fn = [...ancestors].reverse().find((a) =>
    a.type === "FunctionDeclaration" || a.type === "FunctionExpression" || a.type === "ArrowFunctionExpression",
  );
  if (!fn) return false;
  for (const { node } of findNodes(fn, "CallExpression")) {
    const path = calleeMemberPath(node);
    const name = path?.[path.length - 1];
    if (name && GUARD_RE.test(name)) return true;
  }
  for (const { node } of findNodes(fn, "Literal")) {
    const value = literalString(node);
    if (value && GUARD_RE.test(value)) return true;
  }
  return false;
}
