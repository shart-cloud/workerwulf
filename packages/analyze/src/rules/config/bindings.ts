import { registerConfig, type Severity } from "../../engine/rule.js";
import {
  BINDING_BLAST_RADIUS,
  declaredBindings,
  type BindingType,
} from "../../parsers/bindings.js";

/**
 * WF-BIND-01..08 — flag the *presence* of high-blast-radius bindings (PRD §9.2).
 * Each rule fires once per declared binding of its type; the finding explains the
 * demonstrated risk and recommends access controls proportional to blast radius.
 * Presence severities follow PRD §9.2 (which may differ from the intrinsic blast
 * radius in §10 — presence is a posture signal, not a confirmed exploit).
 */
interface BindingRuleSpec {
  id: string;
  type: BindingType;
  severity: Severity;
  label: string;
}

const BINDING_RULES: BindingRuleSpec[] = [
  { id: "WF-BIND-01", type: "hyperdrive", severity: "high", label: "Hyperdrive" },
  { id: "WF-BIND-02", type: "secret", severity: "high", label: "Secrets Store" },
  { id: "WF-BIND-03", type: "queue_producer", severity: "medium", label: "Queue producer" },
  { id: "WF-BIND-04", type: "browser", severity: "high", label: "Browser Rendering" },
  { id: "WF-BIND-05", type: "mtls_certificate", severity: "high", label: "mTLS certificate" },
  { id: "WF-BIND-06", type: "analytics_engine", severity: "medium", label: "Analytics Engine" },
  { id: "WF-BIND-07", type: "vectorize", severity: "medium", label: "Vectorize" },
  { id: "WF-BIND-08", type: "send_email", severity: "high", label: "send_email" },
];

for (const spec of BINDING_RULES) {
  const blast = BINDING_BLAST_RADIUS[spec.type];
  registerConfig({
    id: spec.id,
    title: `${spec.label} binding — ${blast.risk}`,
    severity: spec.severity,
    probe: blast.probe,
    family: "G",
    check(ctx) {
      const matches = declaredBindings(ctx.config).filter((b) => b.type === spec.type);
      return matches.map((b) => ({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `${ctx.configPath}:${b.configKey}`,
        message:
          `${spec.label} binding "${b.name}" is declared. ${blast.probe} demonstrated that this ` +
          `binding type yields ${blast.risk} (category: ${blast.category}) to any code path that ` +
          `reads env.${b.name}. A binding is the Worker's entire authority surface — its presence ` +
          "is the blast radius if any untrusted input reaches it.",
        remediation:
          "Restrict the Worker's routes to authenticated paths and treat this binding as a " +
          "high-value capability: gate every code path that reaches it, and consider an " +
          "intermediary service binding that allowlists the operations actually needed.",
        probe: this.probe,
        family: this.family,
        evidence: [
          { type: "binding", label: `${spec.type}:${b.name}`, inline: b.configKey },
        ],
      }));
    },
  });
}
