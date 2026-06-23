import type { AstNode } from "../../ast/parse.js";
import { locAt } from "../../ast/parse.js";
import {
  calleeMethodName,
  findEnvAccess,
  isStringConcat,
  referencesRequestInput,
} from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import { bindingNamesOfType } from "../../parsers/bindings.js";
import { isSqlSink } from "./resource.js";

const SINK_ANCESTORS = new Set(["ReturnStatement", "TemplateLiteral", "CallExpression", "NewExpression"]);

/**
 * WF-BUSE-01 — Family G. Reading env.HYPERDRIVE.connectionString. Static twin of
 * W-CAP-01: the connection string carries the backing database's host, user, and
 * password in plaintext to any code path that reads it.
 */
registerSource({
  id: "WF-BUSE-01",
  title: "Hyperdrive connectionString read — credential exposure path",
  severity: "high",
  probe: "W-CAP-01",
  family: "G",
  check(ctx) {
    const hyperdrive = bindingNamesOfType(ctx.config, "hyperdrive");
    const findings: Finding[] = [];
    for (const { node, ancestors } of findNodes(ctx.source.ast, "StaticMemberExpression")) {
      const property = node["property"] as AstNode | undefined;
      if (property?.type !== "Identifier" || property["name"] !== "connectionString") continue;
      const base = node["object"] as AstNode | undefined;
      if (!base) continue;
      // base must be env.<hyperdrive binding> (or any env binding if config absent)
      const envHit = findEnvAccess(base, ctx.bindingMap.envNames, hyperdrive.size > 0 ? hyperdrive : undefined);
      if (envHit.length === 0) continue;
      const flowsToSink = ancestors.some((a) => SINK_ANCESTORS.has(a.type));
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `env.${envHit[0]!.binding}.connectionString is read` +
          (flowsToSink ? " and flows into a call/response/return" : "") +
          ". W-CAP-01 demonstrated that the Hyperdrive connection string exposes the backing " +
          "database's host, username, and password in plaintext — credential exposure and a direct " +
          "data-exfil path.",
        remediation:
          "Never read or forward connectionString. Issue queries through the Hyperdrive binding's " +
          "client only, keep the connection string server-side, and never place it in a response, " +
          "log, or outbound request.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/**
 * WF-BUSE-02 — Family G. A Browser Rendering binding launched, then a navigation
 * (goto/navigate) to a request-derived URL. Static twin of W-CAP-05: SSRF with a
 * full browser context (internal services, metadata endpoints, cookie theft).
 */
registerSource({
  id: "WF-BUSE-02",
  title: "Browser binding navigated to a request-derived URL — SSRF with a browser",
  severity: "high",
  probe: "W-CAP-05",
  family: "G",
  check(ctx) {
    const browser = bindingNamesOfType(ctx.config, "browser");
    const launchesBrowser = findNodes(ctx.source.ast, "CallExpression").some(({ node }) => {
      if (calleeMethodName(node) !== "launch") return false;
      const args = (node["arguments"] as AstNode[] | undefined) ?? [];
      return args.some(
        (a) => findEnvAccess(a, ctx.bindingMap.envNames, browser.size > 0 ? browser : undefined).length > 0,
      );
    });
    if (!launchesBrowser) return [];

    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const method = calleeMethodName(node);
      if (method !== "goto" && method !== "navigate") continue;
      const args = (node["arguments"] as AstNode[] | undefined) ?? [];
      const target = args[0];
      if (!target || !referencesRequestInput(target)) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `A headless browser launched from the Browser Rendering binding navigates (${method}) to ` +
          "a request-derived URL. W-CAP-05 demonstrated SSRF with a full browser context — reaching " +
          "internal services and cloud metadata endpoints, and rendering authenticated pages.",
        remediation:
          "Allowlist navigable destinations: validate the URL against an explicit host allowlist and " +
          "reject internal/metadata ranges before calling goto/navigate.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/**
 * WF-BUSE-03 — Family G. A service / dispatch binding's fetch() called with a
 * request-derived URL (not a bare forwarded Request). SSRF via the service
 * binding: the target service is reached with an attacker-influenced path.
 */
registerSource({
  id: "WF-BUSE-03",
  title: "Service-binding fetch() with a request-derived URL — SSRF",
  severity: "high",
  probe: "W-BND-03",
  family: "G",
  check(ctx) {
    const targets = new Set([
      ...bindingNamesOfType(ctx.config, "service"),
      ...bindingNamesOfType(ctx.config, "dispatch_namespace"),
    ]);
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (calleeMethodName(node) !== "fetch") continue;
      const callee = node["callee"] as AstNode | undefined;
      const receiver = callee?.["object"] as AstNode | undefined;
      if (!receiver) continue;
      const envHit = findEnvAccess(receiver, ctx.bindingMap.envNames, targets.size > 0 ? targets : undefined);
      if (envHit.length === 0) continue;
      const args = (node["arguments"] as AstNode[] | undefined) ?? [];
      const first = args[0];
      if (!first) continue;
      // Forwarding the original Request unchanged is the intended, safe pattern.
      if (first.type === "Identifier" && /^req(uest)?$/i.test(first["name"] as string)) continue;
      if (!referencesRequestInput(first)) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `env.${envHit[0]!.binding}.fetch() is called with a request-derived URL/target rather ` +
          "than a forwarded Request. An attacker who controls the path/host can reach unintended " +
          "operations on the bound service (SSRF via the service binding).",
        remediation:
          "Forward the original Request unchanged, or construct the target from a fixed base plus " +
          "validated, allowlisted path segments — never from raw request input.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/**
 * WF-BUSE-04 — Family G. SQL built with string concatenation in a sql sink.
 * Static twin of DO-SQL-01..05. (Template-literal interpolation is WF-RES-02.)
 */
registerSource({
  id: "WF-BUSE-04",
  title: "SQL query built with string concatenation",
  severity: "high",
  probe: "DO-SQL-01",
  family: "G",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isSqlSink(node)) continue;
      const args = (node["arguments"] as AstNode[] | undefined) ?? [];
      if (!isStringConcat(args[0])) continue;
      const loc = locAt(ctx.source, node.start);
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.source.path}:${loc.line}`,
        message:
          `${calleeMethodName(node)}() builds its query by string concatenation (+). Concatenated ` +
          "values are not parameterized — request-derived input here is SQL injection. DO-SQL-01..05 " +
          "demonstrated read/write across the Durable Object's SQLite store via this pattern.",
        remediation:
          "Keep the SQL string static and pass values as bound `?` parameters " +
          "(sql.exec(query, ...params) / prepare(query).bind(...params)). Do not concatenate input " +
          "into SQL.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});
