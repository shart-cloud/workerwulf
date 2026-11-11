import type { AstNode } from "../../ast/parse.js";
import { locAt } from "../../ast/parse.js";
import { isModuleScope, isMutableContainer } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";

/**
 * WF-STATE-01 — Family C. `let`/`var` at module scope. Workers reuse an isolate
 * across requests, so module-scope mutable bindings persist and leak state
 * between unrelated requests (and across tenants on shared infrastructure).
 */
registerSource({
  id: "WF-STATE-01",
  title: "Mutable module-scope state (let/var) persists across requests",
  severity: "medium",
  probe: "W-BND-01",
  family: "C",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node, ancestors } of findNodes(ctx.source.ast, "VariableDeclaration")) {
      const kind = node["kind"];
      if (kind !== "let" && kind !== "var") continue;
      if (!isModuleScope(ancestors)) continue;
      const loc = locAt(ctx.source, node.start);
      const names = declaredNames(node);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `Module-scope ${kind} ${names ? `(${names}) ` : ""}declares mutable state. The Workers ` +
          "runtime reuses an isolate across many requests, so this binding's value carries over " +
          "between requests — a cross-request data-leak and cache-poisoning vector.",
        remediation:
          "Move per-request state inside the handler, or persist deliberate shared state in a " +
          "binding (KV/DO/D1) with explicit, request-scoped keys.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/**
 * WF-STATE-02 — Family C. `const` at module scope bound to a mutable container
 * (new Map/Set, [], {}). The reference is const but the contents are mutated and
 * shared across requests.
 */
registerSource({
  id: "WF-STATE-02",
  title: "Module-scope const mutable container shared across requests",
  severity: "medium",
  probe: "W-BND-01",
  family: "C",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node, ancestors } of findNodes(ctx.source.ast, "VariableDeclaration")) {
      if (node["kind"] !== "const") continue;
      if (!isModuleScope(ancestors)) continue;
      const declarators = (node["declarations"] as AstNode[] | undefined) ?? [];
      for (const decl of declarators) {
        if (!isMutableContainer(decl["init"] as AstNode | undefined)) continue;
        const loc = locAt(ctx.source, decl.start);
        const id = decl["id"] as AstNode | undefined;
        const name = id?.type === "Identifier" ? (id["name"] as string) : undefined;
        findings.push({
          rule_id: this.id,
          title: this.title,
          severity: this.severity,
          resource: `${ctx.source.path}:${loc.line}`,
          message:
            `Module-scope const ${name ? `"${name}" ` : ""}holds a mutable container (Map/Set/` +
            "array/object). const freezes the reference, not the contents — entries written during " +
            "one request remain visible to later requests sharing the isolate.",
          remediation:
            "Construct the container inside the handler for per-request isolation, or store shared " +
            "state in a binding with request-scoped keys if cross-request sharing is intended.",
          probe: this.probe,
          family: this.family,
        });
      }
    }
    return findings;
  },
});

function declaredNames(decl: AstNode): string | undefined {
  const declarators = (decl["declarations"] as AstNode[] | undefined) ?? [];
  const names = declarators
    .map((d) => {
      const id = d["id"] as AstNode | undefined;
      return id?.type === "Identifier" ? (id["name"] as string) : undefined;
    })
    .filter((n): n is string => Boolean(n));
  return names.length > 0 ? names.join(", ") : undefined;
}
