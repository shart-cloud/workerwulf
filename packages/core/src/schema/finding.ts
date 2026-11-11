import * as Schema from "effect/Schema";

export const Severity = Schema.Literals(["critical", "high", "medium", "low", "informational"]);
export type Severity = typeof Severity.Type;

/** Lower is more severe. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

export const Evidence = Schema.Struct({
  type: Schema.Literals(["config", "source", "binding", "api", "http"]),
  label: Schema.String,
  /** Short inline text payload. */
  inline: Schema.optionalKey(Schema.String),
  /** Relative path to a larger artifact. */
  file: Schema.optionalKey(Schema.String),
});
export type Evidence = typeof Evidence.Type;

export const Finding = Schema.Struct({
  rule_id: Schema.String,
  title: Schema.String,
  severity: Severity,
  /** Human-readable resource: "wrangler.toml", "src/index.ts:42", "script:prey". */
  resource: Schema.String,
  /** What's wrong and why. */
  message: Schema.String,
  /** How to fix. */
  remediation: Schema.String,
  /** The workerwulf probe or finding that demonstrated this weakness: "W-CAP-01". */
  probe: Schema.String,
  /** RULES_PRD family: "A".."H". */
  family: Schema.String,
  evidence: Schema.optionalKey(Schema.Array(Evidence)),
});
export type Finding = typeof Finding.Type;

/**
 * Stable identity for a finding across scans: the same rule firing on the same
 * resource is the same finding. Pair it with the account when storing.
 */
export const findingKey = (finding: Pick<Finding, "rule_id" | "resource">): string =>
  `${finding.rule_id}|${finding.resource}`;
