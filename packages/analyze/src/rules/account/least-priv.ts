import { registerAccount, type Finding, type ScriptMetadata } from "../../engine/rule.js";
import { BINDING_BLAST_RADIUS } from "../../parsers/bindings.js";

/**
 * WF-PRIV-01 — declared-but-unused binding (excess capability). The delta between
 * what a script's metadata declares and what its deployed code references is
 * unused authority: blast radius with no benefit. Severity inherits from the
 * binding's blast-radius classification (§10).
 */
registerAccount({
  id: "WF-PRIV-01",
  title: "Declared binding not referenced in deployed script — excess capability",
  severity: "medium",
  probe: "W-BND-01",
  family: "G",
  check(ctx) {
    const findings: Finding[] = [];
    for (const script of ctx.scripts) {
      // Need parsed usage to make the diff; without it we can't claim "unused".
      if (!script.bindingMap) continue;
      const used = script.bindingMap.used;
      for (const binding of script.declared) {
        if (used.has(binding.name)) continue;
        const blast = BINDING_BLAST_RADIUS[binding.type];
        const caveat = script.bindingMap.envDestructured
          ? " (note: env is destructured in this script, which can hide references — verify before removing)"
          : "";
        findings.push({
          rule_id: this.id,
          title: this.title,
          severity: blast.severity === "informational" ? "low" : blast.severity,
          resource: `script:${script.name}:binding:${binding.name}`,
          message:
            `Binding "${binding.name}" (${binding.type}) is declared on the deployed script but is ` +
            `never referenced in its code. Declared authority you don't use is pure blast radius: ` +
            `${blast.probe} showed this binding type enables ${blast.risk}${caveat}.`,
          remediation:
            "Remove the unused binding from the Worker's configuration so a future code change (or " +
            "an injection) cannot reach a capability the Worker never needed.",
          probe: this.probe,
          family: this.family,
          evidence: [{ type: "binding", label: `${binding.type}:${binding.name}` }],
        });
      }
    }
    return findings;
  },
});

/**
 * WF-PRIV-02 — high-blast-radius binding on a publicly-routed script. Compound
 * risk: a powerful capability reachable from an unauthenticated path.
 * Auth detection is heuristic — presence of any route is treated as public
 * (PRD §12.1); the finding says so.
 */
registerAccount({
  id: "WF-PRIV-02",
  title: "High-blast-radius binding on a publicly-routed script",
  severity: "high",
  probe: "W-CAP-*",
  family: "G",
  check(ctx) {
    const findings: Finding[] = [];
    for (const script of ctx.scripts) {
      if (script.routes.length === 0) continue;
      const highBlast = script.declared.filter((b) => isHighBlast(b));
      if (highBlast.length === 0) continue;
      const names = highBlast.map((b) => `${b.name} (${b.type})`).join(", ");
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `script:${script.name}`,
        message:
          `Script "${script.name}" is bound to high-blast-radius capabilities (${names}) and is ` +
          `publicly routed (${script.routes.map((r) => r.pattern).join(", ")}). A reachable ` +
          "powerful binding is a compound risk — any flaw on the request path reaches a capability " +
          "that can exfiltrate data or pivot. (Auth is not verified; route presence is treated as " +
          "public.)",
        remediation:
          "Put the high-blast-radius binding behind an authenticated, internal-only path — e.g. an " +
          "intermediary service binding with operation allowlisting — and keep the public route " +
          "scoped to low-authority handlers.",
        probe: this.probe,
        family: this.family,
        evidence: highBlast.map((b) => ({ type: "binding" as const, label: `${b.type}:${b.name}` })),
      });
    }
    return findings;
  },
});

function isHighBlast(binding: ScriptMetadata["declared"][number]): boolean {
  const sev = BINDING_BLAST_RADIUS[binding.type].severity;
  return sev === "critical" || sev === "high";
}
