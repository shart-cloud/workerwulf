import type { AstNode } from "../../ast/parse.js";
import { locAt } from "../../ast/parse.js";
import { isCallTo, isConstructOf, staticStringValue } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";

/** WF-INJ-01 — Family B. Direct eval() call. */
registerSource({
  id: "WF-INJ-01",
  title: "eval() — dynamic code execution sink",
  severity: "high",
  probe: "AI-INJ-*",
  family: "B",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isCallTo(node, "eval")) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          "Direct eval() call. Any attacker-influenced string reaching eval is remote code " +
          "execution inside the Worker isolate, with access to every binding in env.",
        remediation:
          "Remove eval(). Parse data with JSON.parse, dispatch on an allowlist, or use a sandboxed " +
          "interpreter — never evaluate request-derived strings as code.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/** WF-INJ-02 — Family B. new Function() construction. */
registerSource({
  id: "WF-INJ-02",
  title: "new Function() — dynamic code construction",
  severity: "high",
  probe: "AI-INJ-*",
  family: "B",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "NewExpression")) {
      if (!isConstructOf(node, "Function")) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          "new Function() compiles a string into executable code — the same RCE sink as eval(). " +
          "Attacker-influenced input reaching the constructor body executes with full isolate and " +
          "binding access.",
        remediation:
          "Replace new Function() with static code paths or a data-driven dispatch table. Do not " +
          "build functions from request-derived strings.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/** WF-INJ-03 — Family B. setTimeout / setInterval with a string first argument. */
registerSource({
  id: "WF-INJ-03",
  title: "setTimeout/setInterval with a string argument — implicit eval",
  severity: "high",
  probe: "AI-INJ-*",
  family: "B",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isCallTo(node, "setTimeout") && !isCallTo(node, "setInterval")) continue;
      const args = (node["arguments"] as AstNode[] | undefined) ?? [];
      const first = args[0];
      if (!first || staticStringValue(first) === undefined) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          "setTimeout/setInterval called with a string first argument evaluates that string as " +
          "code — the same RCE sink as eval(). Any attacker-influenced portion executes with full " +
          "isolate and binding access.",
        remediation:
          "Pass a function reference instead of a string: setTimeout(() => fn(), ms).",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/** WF-INJ-04 — Family B. Dynamic import() with a non-literal specifier. */
registerSource({
  id: "WF-INJ-04",
  title: "Dynamic import() with a non-literal specifier",
  severity: "medium",
  probe: "AI-INJ-*",
  family: "B",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "ImportExpression")) {
      const source = node["source"] as AstNode | undefined;
      if (source && staticStringValue(source) !== undefined) continue; // static specifier is fine
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          "import() is called with a computed specifier. If any part derives from request input, " +
          "an attacker can steer which module loads and executes inside the isolate.",
        remediation:
          "Import from a static, literal specifier, or map untrusted input through an explicit " +
          "allowlist of permitted module paths before importing.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});
