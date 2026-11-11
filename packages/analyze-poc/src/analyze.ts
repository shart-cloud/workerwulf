/**
 * The `wulf audit --source` pipeline without a filesystem: config text and
 * source files come in as strings. It reuses the CLI's parser, rules and report
 * shaping unchanged, so the output can be compared with `wulf audit --json`.
 */
import { buildBindingMap } from "@wulf/cli/src/ast/binding-map.js";
import { parse } from "@wulf/cli/src/ast/parse.js";
import { buildReport, toSerializable, type FindingGroup } from "@wulf/cli/src/engine/output.js";
import type { Finding, Severity } from "@wulf/cli/src/engine/rule.js";
import { atOrAbove, runConfigRules, runSourceRules } from "@wulf/cli/src/engine/runner.js";
import { parseWranglerText, resolveEnvironments } from "@wulf/cli/src/parsers/wrangler.js";
import "@wulf/cli/src/rules/index.js";

export interface AnalyzeInput {
  /** e.g. "wrangler.toml" — its extension selects TOML or JSON(C). */
  configPath: string;
  configText: string;
  /** Source files in scan order, paths relative to the scan root. */
  files: Array<{ path: string; text: string }>;
  /** Minimum severity to report; `wulf audit` defaults to "low". */
  severity?: Severity;
}

export interface AnalyzeOutput {
  sources: Array<{ source: string; findings: Finding[] }>;
  notes: string[];
}

export function analyzeProject(input: AnalyzeInput): AnalyzeOutput {
  const groups: FindingGroup[] = [];
  const notes: string[] = [];
  const parsed = parseWranglerText(input.configPath, input.configText);

  // Mirrors runAudit: config rules per resolved env, deduped by (rule, resource).
  const configFindings: Finding[] = [];
  const seen = new Set<string>();
  for (const env of resolveEnvironments(parsed.config)) {
    const outcome = runConfigRules({ config: env.config, configPath: input.configPath, envName: env.name });
    for (const f of outcome.findings) {
      const key = `${f.rule_id}::${f.resource}`;
      if (env.name === "default") {
        seen.add(key);
        configFindings.push(f);
      } else if (!seen.has(key)) {
        seen.add(key);
        configFindings.push({ ...f, resource: `${f.resource} [env:${env.name}]` });
      }
    }
  }
  groups.push({ kind: "config", source: input.configPath, findings: configFindings });

  for (const file of input.files) {
    const source = parse(file.path, file.text);
    if (source.errors.length > 0) {
      notes.push(`Parse warnings in ${file.path}: ${source.errors.length} (continuing)`);
    }
    const outcome = runSourceRules({
      config: parsed.config,
      configPath: input.configPath,
      source,
      bindingMap: buildBindingMap(source),
    });
    groups.push({ kind: "source", source: file.path, findings: outcome.findings });
  }

  const min = input.severity ?? "low";
  const filtered = groups.map((g) => ({ ...g, findings: atOrAbove(g.findings, min) }));
  const { sources } = toSerializable(buildReport("-", "-", filtered));
  return { sources, notes };
}
