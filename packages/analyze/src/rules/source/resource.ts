import type { AstNode } from "../../ast/parse.js";
import { locAt } from "../../ast/parse.js";
import {
  calleeMemberPath,
  calleeMethodName,
  isCallTo,
  isInLoop,
  templateHasExpressions,
} from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";

/**
 * WF-RES-01 — Family F. fetch() inside a loop with no AbortSignal/timeout. An
 * unbounded fan-out of subrequests with no per-request deadline exhausts the
 * Worker's CPU/subrequest budget and can be driven into a self-DoS.
 */
registerSource({
  id: "WF-RES-01",
  title: "fetch() in a loop without a timeout/AbortSignal",
  severity: "medium",
  probe: "F-002",
  family: "F",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node, ancestors } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isCallTo(node, "fetch")) continue;
      if (!isInLoop(ancestors)) continue;
      if (hasSignalOption(node)) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          "fetch() is called inside a loop with no AbortSignal/timeout. Without a per-request " +
          "deadline an unbounded number of subrequests can exhaust the Worker's CPU and subrequest " +
          "limits — a resource-exhaustion / self-DoS vector.",
        remediation:
          "Bound the iteration count and pass an AbortSignal (AbortSignal.timeout(ms)) to each " +
          "fetch; consider batching with a concurrency cap.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/**
 * WF-RES-02 — Family F. SQL built with template-literal interpolation. Static
 * twin of DO-SQL-01: `${...}` inside a sql.exec()/prepare() query string is
 * unparameterized and injectable. (String `+` concatenation is WF-BUSE-04.)
 */
registerSource({
  id: "WF-RES-02",
  title: "SQL query built with template-literal interpolation",
  severity: "high",
  probe: "DO-SQL-01",
  family: "F",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isSqlSink(node)) continue;
      const args = (node["arguments"] as AstNode[] | undefined) ?? [];
      const first = args[0];
      if (!templateHasExpressions(first)) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `${calleeMethodName(node)}() receives a template literal with interpolated ${"${...}"} ` +
          "expressions. Interpolated values are not parameterized — if any derive from request " +
          "input this is SQL injection. DO-SQL-01 demonstrated the blast radius across the " +
          "Durable Object's SQLite store.",
        remediation:
          "Use parameterized queries: keep the SQL string static and pass values as bound `?` " +
          "parameters (sql.exec(query, ...params) / prepare(query).bind(...params)).",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/** True if the call's options object (2nd arg of fetch) declares a `signal`. */
function hasSignalOption(call: AstNode): boolean {
  const args = (call["arguments"] as AstNode[] | undefined) ?? [];
  const options = args[1];
  if (options?.type !== "ObjectExpression") return false;
  const props = (options["properties"] as AstNode[] | undefined) ?? [];
  return props.some((p) => {
    const key = p["key"] as AstNode | undefined;
    return key?.type === "Identifier" && key["name"] === "signal";
  });
}

/** True if the call is a SQL sink: *.sql.exec(), or *.prepare(). */
export function isSqlSink(call: AstNode): boolean {
  const path = calleeMemberPath(call);
  if (!path) return false;
  const method = path[path.length - 1];
  if (method === "prepare") return true;
  if ((method === "exec" || method === "run") && path.includes("sql")) return true;
  return false;
}
