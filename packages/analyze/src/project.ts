import { buildBindingMap } from "./ast/binding-map.js";
import { parse } from "./ast/parse.js";
import type { ProjectFiles } from "./engine/files.js";
import type { FindingGroup } from "./engine/report.js";
import type { Finding, Severity } from "./engine/rule.js";
import { atOrAbove, runConfigRules, runSourceRules } from "./engine/runner.js";
import { resolveEnvironments, type WranglerConfig } from "./parsers/wrangler.js";

export interface ProjectSource {
  /** Path as shown in findings. */
  path: string;
  /** The file's text, or a function that reads it (a throw becomes a note). */
  text: string | (() => string);
}

export interface ProjectInput {
  /** The config's path as shown in findings, e.g. "wrangler.toml". */
  configPath: string;
  config: WranglerConfig;
  /** Source files in scan order. Empty for a config-only audit. */
  sources: readonly ProjectSource[];
  /** Files next to the config, for supply-chain rules. */
  files?: ProjectFiles;
  ignore?: ReadonlySet<string>;
  /** Minimum severity to keep; `wulf audit` defaults to "low". */
  severity?: Severity;
}

export interface ProjectAudit {
  /** The config's group, then one group per source file. */
  groups: FindingGroup[];
  /** Human-readable notes: parse warnings and files that failed to scan. */
  notes: string[];
}

/**
 * `wulf audit` for one wrangler config, without a filesystem. Config rules run
 * for every resolved environment, deduped by (rule, resource); source rules run
 * once per file.
 */
export function auditProject(input: ProjectInput): ProjectAudit {
  const ignore = input.ignore ?? new Set<string>();
  const keep = (findings: Finding[]): Finding[] =>
    atOrAbove(ignore.size === 0 ? findings : findings.filter((f) => !ignore.has(f.rule_id)), input.severity ?? "low");
  const groups: FindingGroup[] = [];
  const notes: string[] = [];

  const configFindings: Finding[] = [];
  const seen = new Set<string>();
  for (const env of resolveEnvironments(input.config)) {
    const outcome = runConfigRules({
      config: env.config,
      configPath: input.configPath,
      envName: env.name,
      ...(input.files && { files: input.files }),
    });
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
  groups.push({ kind: "config", source: input.configPath, findings: keep(configFindings) });

  for (const file of input.sources) {
    try {
      const text = typeof file.text === "string" ? file.text : file.text();
      const source = parse(file.path, text);
      if (source.errors.length > 0) {
        notes.push(`Parse warnings in ${file.path}: ${source.errors.length} (continuing)`);
      }
      const outcome = runSourceRules({
        config: input.config,
        configPath: input.configPath,
        source,
        bindingMap: buildBindingMap(source),
      });
      groups.push({ kind: "source", source: file.path, findings: keep(outcome.findings) });
    } catch (err) {
      notes.push(`Failed to scan ${file.path}: ${(err as Error).message}`);
    }
  }

  return { groups, notes };
}
