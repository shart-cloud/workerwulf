import { registerAccount, type Finding } from "../../engine/rule.js";

/**
 * WF-DRIFT-01 — the deployed script content diverges from local source. Drift
 * means the audited source is not what is running: a source-level scan may miss
 * what is actually deployed. Build transforms (bundling, minification, tree-
 * shaking) cause benign drift — the finding says so, and exists partly to
 * surface that bundles differ from source (PRD §12.1).
 */
registerAccount({
  id: "WF-DRIFT-01",
  title: "Deployed script content diverges from local source",
  severity: "medium",
  probe: "—",
  family: "G",
  check(ctx) {
    if (!ctx.localSources || ctx.localSources.size === 0) return [];
    const findings: Finding[] = [];
    for (const script of ctx.scripts) {
      const local = ctx.localSources.get(script.name);
      if (!local || script.content === undefined) continue;
      if (normalize(local.text) === normalize(script.content)) continue;
      findings.push({
        rule_id: this.id,
        title: this.title,
        severity: this.severity,
        resource: `script:${script.name}`,
        message:
          `The deployed content of "${script.name}" does not match the local source provided. The ` +
          "running code is not what was audited locally — a source scan can miss what is actually " +
          "deployed. Build transforms (bundling/minification) can cause benign drift; treat this as " +
          "a prompt to confirm the deployment provenance, not proof of tampering.",
        remediation:
          "Re-deploy from the audited source, or scan the deployed bundle directly. Pin a build/" +
          "deploy pipeline so deployed content is reproducible from a known commit.",
        probe: this.probe,
        family: this.family,
      });
    }
    return findings;
  },
});

/** Collapse insignificant whitespace so trivial formatting isn't reported as drift. */
function normalize(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}
