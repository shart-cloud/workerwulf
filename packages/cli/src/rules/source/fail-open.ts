import type { AstNode } from "../../ast/parse.js";
import { locAt } from "../../ast/parse.js";
import { calleeMethodName, isSuccessValue } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";

const GUARD_NAME_RE =
  /(guard|scan|check|verify|validate|authoriz|authenticat|filter|moderat|detect|inspect|sanitiz)/i;

/**
 * WF-FAIL-01 — Family E. Static twin of F-001 (guard gate fails open).
 * A catch block that returns a success-shaped value means scanner/guard errors
 * fail open: unscanned input reaches execution when the guard degrades.
 */
registerSource({
  id: "WF-FAIL-01",
  title: "Catch block returns a success value — guard fails open",
  severity: "high",
  probe: "F-001",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CatchClause")) {
      const body = node["body"] as AstNode | undefined;
      const statements = (body?.["body"] as AstNode[] | undefined) ?? [];
      for (const stmt of returnStatementsIn(statements)) {
        const arg = stmt["argument"] as AstNode | undefined;
        if (isSuccessValue(arg)) {
          const loc = locAt(ctx.source, stmt.start);
          findings.push({
            rule_id: this.id,
            title: this.title,
            severity: this.severity,
            resource: `${ctx.source.path}:${loc.line}`,
            message:
              "Catch block returns a success-shaped value (e.g. new Response(...), " +
              "{ decision: \"allow\" }, { safe: true }, status 200). F-001 demonstrated this pattern " +
              "lets unscanned input reach execution under a block policy when the guard/scanner " +
              "errors — the failure mode is allow, not deny.",
            remediation:
              "Return a block/deny verdict (or re-throw) on error paths in guard helpers, so a " +
              "degraded scanner fails closed.",
            probe: this.probe,
            family: this.family,
            evidence: [
              { type: "source", label: `${ctx.source.path}:${loc.line}`, inline: snippet(ctx.source.text, stmt) },
            ],
          });
        }
      }
    }
    return findings;
  },
});

/**
 * WF-FAIL-02 — Family E. Empty catch block: errors are silently swallowed,
 * which on a guard/scanner path is fail-open by omission.
 */
registerSource({
  id: "WF-FAIL-02",
  title: "Empty catch block — silent error swallowing",
  severity: "medium",
  probe: "F-001",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CatchClause")) {
      const body = node["body"] as AstNode | undefined;
      const statements = (body?.["body"] as AstNode[] | undefined) ?? [];
      if (statements.length > 0) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          "Empty catch block swallows every error silently. On any security-relevant path this is " +
          "fail-open: the failure is invisible and execution continues as if nothing went wrong.",
        remediation:
          "Handle the error explicitly — log it and fail closed (block/deny or re-throw). Never " +
          "leave a catch body empty on a guard, auth, or scanner path.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/**
 * WF-FAIL-03 — Family E. A try wrapping a guard/scanner call whose catch neither
 * re-throws nor returns: the error is swallowed and control falls through past
 * the guard. WF-FAIL-01 owns the case where the catch returns a success value;
 * this rule covers swallow-and-continue.
 */
registerSource({
  id: "WF-FAIL-03",
  title: "Guard call wrapped in try whose catch does not fail closed",
  severity: "high",
  probe: "F-001",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "TryStatement")) {
      const handler = node["handler"] as AstNode | undefined;
      if (!handler) continue;
      const block = node["block"] as AstNode | undefined;
      if (!block || !callsGuard(block)) continue;

      const handlerBody = handler["body"] as AstNode | undefined;
      const handlerStmts = (handlerBody?.["body"] as AstNode[] | undefined) ?? [];
      const throwsOrReturns = handlerStmts.some(
        (s) => containsType(s, "ThrowStatement") || containsType(s, "ReturnStatement"),
      );
      if (throwsOrReturns) continue; // re-throws, or WF-FAIL-01 handles the return

      const loc = locAt(ctx.source, handler.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          "A guard/scanner call is wrapped in try/catch, but the catch neither re-throws nor " +
          "returns a deny verdict — the error is swallowed and execution continues past the guard. " +
          "F-001 demonstrated unscanned input reaching execution when the guard degraded.",
        remediation:
          "In the catch, fail closed: re-throw, or return an explicit block/deny verdict so a " +
          "degraded guard cannot be bypassed by inducing an error.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/** True if the block contains a call to a guard/scanner-named function. */
function callsGuard(block: AstNode): boolean {
  for (const { node } of findNodes(block, "CallExpression")) {
    const method = calleeMethodName(node);
    if (method && GUARD_NAME_RE.test(method)) return true;
  }
  return false;
}

function containsType(node: AstNode, type: string): boolean {
  return findNodes(node, type).length > 0;
}

/** Direct return statements inside a block (not descending into nested functions). */
function returnStatementsIn(statements: AstNode[]): AstNode[] {
  const out: AstNode[] = [];
  for (const node of findNodesInStatements(statements, "ReturnStatement")) out.push(node);
  return out;
}

function findNodesInStatements(statements: AstNode[], type: string): AstNode[] {
  const out: AstNode[] = [];
  for (const stmt of statements) {
    for (const { node } of findNodes(stmt, type)) out.push(node);
  }
  return out;
}

function snippet(text: string, node: AstNode): string {
  return text.slice(node.start, node.end).replace(/\s+/g, " ").slice(0, 120);
}
