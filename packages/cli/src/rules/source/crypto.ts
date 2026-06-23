import type { AstNode } from "../../ast/parse.js";
import { locAt } from "../../ast/parse.js";
import {
  calleeMemberPath,
  exprName,
  isTimingUnsafeComparison,
  nameLooksSecret,
} from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import { secretBindingNames } from "../../parsers/bindings.js";

const SECURITY_CONTEXT_RE =
  /(token|nonce|secret|session|salt|csrf|otp|password|passcode|apikey|api[_-]?key|uuid|guid|cookie)/i;

/**
 * WF-CRYPTO-01 — Family D. Equality comparison of a secret with `===`/`==`.
 * String/array `===` short-circuits on the first differing byte, leaking length
 * and prefix via timing. Secret comparisons must be constant-time.
 */
registerSource({
  id: "WF-CRYPTO-01",
  title: "Timing-unsafe comparison of a secret",
  severity: "high",
  probe: "W-CAP-02",
  family: "D",
  check(ctx) {
    const secretNames = secretBindingNames(ctx.config);
    const isSecret = (name: string): boolean =>
      nameLooksSecret(name) || secretNames.has(name);
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "BinaryExpression")) {
      if (!isTimingUnsafeComparison(node, isSecret)) continue;
      const loc = locAt(ctx.source, node.start);
      const operand =
        [exprName(node["left"] as AstNode), exprName(node["right"] as AstNode)].find(
          (n) => n && isSecret(n),
        ) ?? "secret";
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `"${operand}" is compared with ${node["operator"]}, a non-constant-time equality check. ` +
          "It short-circuits on the first differing byte, leaking the secret's length and a prefix " +
          "through response timing — enabling byte-by-byte recovery of tokens/keys.",
        remediation:
          "Compare secrets with a constant-time function (crypto.subtle.timingSafeEqual over equal-" +
          "length buffers), never with === / ==.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/**
 * WF-CRYPTO-02 — Family D. Math.random() used in a security context (token,
 * nonce, session id, ...). Math.random is not cryptographically secure and is
 * predictable; security values must come from crypto.getRandomValues.
 */
registerSource({
  id: "WF-CRYPTO-02",
  title: "Math.random() used for a security-relevant value",
  severity: "medium",
  probe: "W-CAP-02",
  family: "D",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node, ancestors } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (!path || path[0] !== "Math" || path[1] !== "random") continue;
      const context = securityContextName(ancestors);
      if (!context) continue; // not obviously security-relevant — skip to limit false positives
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `Math.random() feeds a security-relevant value ("${context}"). Math.random is not a CSPRNG ` +
          "— its output is predictable, so tokens/nonces/ids built from it can be guessed or " +
          "forged.",
        remediation:
          "Generate security values with crypto.getRandomValues() (or crypto.randomUUID() for ids).",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/** If the Math.random() call sits in a security-named binding/assignment, return that name. */
function securityContextName(ancestors: AstNode[]): string | undefined {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const a = ancestors[i]!;
    let name: string | undefined;
    if (a.type === "VariableDeclarator") {
      const id = a["id"] as AstNode | undefined;
      if (id?.type === "Identifier") name = id["name"] as string;
    } else if (a.type === "ObjectProperty" || a.type === "PropertyDefinition") {
      const key = a["key"] as AstNode | undefined;
      if (key?.type === "Identifier") name = key["name"] as string;
    } else if (a.type === "AssignmentExpression") {
      name = exprName(a["left"] as AstNode | undefined);
    }
    if (name && SECURITY_CONTEXT_RE.test(name)) return name;
  }
  return undefined;
}
