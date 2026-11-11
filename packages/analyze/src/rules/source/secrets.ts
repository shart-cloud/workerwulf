import type { AstNode } from "../../ast/parse.js";
import { locAt } from "../../ast/parse.js";
import {
  calleeMemberPath,
  findEnvAccess,
  isConstructOf,
  looksLikeSecret,
} from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import { bindingNamesOfType, secretBindingNames } from "../../parsers/bindings.js";

/**
 * WF-SEC-01 — Family A. String literal matching token/key patterns
 * (sk_live_*, AWS keys, GitHub PATs, JWTs, PEM keys, long hex blobs).
 */
registerSource({
  id: "WF-SEC-01",
  title: "Hardcoded secret literal in source",
  severity: "high",
  probe: "W-CAP-02",
  family: "A",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "Literal")) {
      if (!looksLikeSecret(node)) continue;
      const loc = locAt(ctx.source, node.start);
      const raw = String(node["value"]);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          "A string literal matches a known secret/token shape (vendor key prefix, JWT, PEM key, " +
          "or high-entropy hex). Hardcoded credentials ship in the bundle and end up in source " +
          "control, deploy logs, and the deployed script content readable via the API.",
        remediation:
          "Move the value to a Worker secret (`wrangler secret put`) or the Secrets Store and read " +
          "it from env at runtime. Rotate the exposed credential.",
        probe: this.probe,
        family: this.family,
        evidence: [{ type: "source", label: redact(raw) }],
      });
    }
    return findings;
  },
});

/**
 * WF-SEC-02 — Family A. console.* logging of a secret-classified binding value.
 * Logs land in `wrangler tail` / observability sinks; W-CAP-01 showed an upstream
 * logger leaking Hyperdrive credentials this way.
 */
registerSource({
  id: "WF-SEC-02",
  title: "Secret-classified binding logged via console.*",
  severity: "high",
  probe: "W-CAP-01",
  family: "A",
  check(ctx) {
    const secretNames = secretBindingNames(ctx.config);
    if (secretNames.size === 0) return [];
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (!path || path[0] !== "console") continue;
      const args = (node["arguments"] as AstNode[] | undefined) ?? [];
      const leaked = args.flatMap((a) =>
        findEnvAccess(a, ctx.bindingMap.envNames, secretNames),
      );
      if (leaked.length === 0) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `console.${path[path.length - 1]}() is passed a secret-classified binding ` +
          `(${[...new Set(leaked.map((l) => `env.${l.binding}`))].join(", ")}). W-CAP-01 ` +
          "demonstrated credential leakage when binding values reach logs — Worker logs are " +
          "readable via wrangler tail and any connected observability sink.",
        remediation:
          "Never log binding values. Log a redacted/derived identifier instead, and scrub secret " +
          "fields before they reach console.* or any logger.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/**
 * WF-SEC-03 — Family A. A secret-classified binding value flows into a Response
 * body or a value returned from the handler without redaction. Hyperdrive's
 * connectionString is owned by WF-BUSE-01, so it is excluded here to avoid
 * double-reporting.
 */
registerSource({
  id: "WF-SEC-03",
  title: "Secret-classified binding returned in a response without redaction",
  severity: "high",
  probe: "W-CAP-02",
  family: "A",
  check(ctx) {
    const hyperdrive = bindingNamesOfType(ctx.config, "hyperdrive");
    const secretNames = new Set(
      [...secretBindingNames(ctx.config)].filter((n) => !hyperdrive.has(n)),
    );
    if (secretNames.size === 0) return [];
    const findings: Finding[] = [];

    const report = (container: AstNode, label: string): void => {
      const leaked = findEnvAccess(container, ctx.bindingMap.envNames, secretNames);
      if (leaked.length === 0) return;
      const loc = locAt(ctx.source, container.start);
      findings.push({
        rule_id: "WF-SEC-03",
        title: "Secret-classified binding returned in a response without redaction",
        severity: "high",
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `${label} includes a secret-classified binding ` +
          `(${[...new Set(leaked.map((l) => `env.${l.binding}`))].join(", ")}). The deployed ` +
          "script content and any response are attacker-observable; W-CAP-02 demonstrated " +
          "plaintext secret retrieval when a binding value reaches the response surface.",
        remediation:
          "Do not place binding/secret values in response bodies. Return only the data the caller " +
          "is authorized to see, and redact secret fields explicitly.",
        probe: "W-CAP-02",
        family: "A",
      });
    };

    for (const { node } of findNodes(ctx.source.ast, "NewExpression")) {
      if (isConstructOf(node, "Response")) report(node, "new Response(...) body");
    }
    for (const { node } of findNodes(ctx.source.ast, "ReturnStatement")) {
      const arg = node["argument"] as AstNode | undefined;
      if (!arg) continue;
      // `return new Response(...)` is already covered by the Response pass.
      if (isConstructOf(arg, "Response")) continue;
      report(arg, "returned value");
    }
    return findings;
  },
});

/** Show only the first few characters so the report doesn't re-leak the secret. */
function redact(value: string): string {
  if (value.length <= 6) return "******";
  return `${value.slice(0, 4)}…(${value.length} chars, redacted)`;
}
