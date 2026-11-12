import type { AccountSnapshot, Coverage, RawNamespace, ScriptSnapshot } from "@wulf/core";

import { buildBindingMap, type BindingMap } from "./ast/binding-map.js";
import { parse } from "./ast/parse.js";

/**
 * Largest bundle parsed in-process by default when a limit is asked for. Measured
 * on a real deployment (slice 2): a 1.47 MB parse left 104 MiB of WASM memory,
 * and a 3.44 MB parse got the isolate killed. Bundles above this are not analysed
 * in-Worker, and a coverage entry says so.
 */
export const WORKER_PARSE_LIMIT_BYTES = 1_500_000;

/**
 * Everything the account rules read about one deployed script, with the bundle
 * text replaced by what was derived from it. Plain JSON, so it can be stored as
 * a ScanHub batch: it never holds bundle content or binding values.
 */
export interface ScriptSummary {
  readonly name: string;
  /** Binding `type` and `name` only. Absent when the bindings read did not complete. */
  readonly bindings?: ReadonlyArray<{ readonly type: string; readonly name: string }>;
  readonly routes?: ReadonlyArray<string>;
  /** Absent when there was no content, or it was not analysed (see coverage). */
  readonly usage?: BindingUsage;
  /** UTF-16 length of the downloaded bundle, when there was one. */
  readonly contentLength?: number;
}

/** The parts of a `BindingMap` that account rules read. */
export interface BindingUsage {
  /** Binding names referenced in the bundle, sorted. */
  readonly used: ReadonlyArray<string>;
  readonly envDestructured: boolean;
}

/** An account snapshot with every script summarized. Safe to persist. */
export interface AccountSummary {
  readonly accountId: string;
  readonly scripts: ReadonlyArray<ScriptSummary>;
  readonly namespaces: ReadonlyArray<RawNamespace>;
  readonly coverage: ReadonlyArray<Coverage>;
}

export interface SummarizeOptions {
  /** Skip parsing bundles longer than this (UTF-16 length). Default: no limit. */
  readonly maxParseLength?: number;
}

export interface SummarizedScript {
  readonly summary: ScriptSummary;
  /** Coverage added by summarizing: an `analyze` entry when the bundle was not parsed. */
  readonly coverage: ReadonlyArray<Coverage>;
}

/** Summarize one collected script. Parses its bundle, then drops the text. */
export function summarizeScript(script: ScriptSnapshot, options: SummarizeOptions = {}): SummarizedScript {
  const base = {
    name: script.name,
    ...(script.bindings !== undefined && {
      bindings: script.bindings.map((b) => ({ type: b.type, name: b.name })),
    }),
    ...(script.routes !== undefined && { routes: [...script.routes] }),
  };
  if (script.content === undefined) return { summary: base, coverage: [] };

  const contentLength = script.content.length;
  const limit = options.maxParseLength;
  if (limit !== undefined && contentLength > limit) {
    return {
      summary: { ...base, contentLength },
      coverage: [
        {
          target: `script:${script.name}`,
          op: "analyze",
          status: "unavailable",
          detail: `bundle is ${contentLength} characters, over the ${limit} in-Worker parse limit`,
        },
      ],
    };
  }
  const map = buildBindingMap(parse(`script:${script.name}`, script.content));
  return { summary: { ...base, contentLength, usage: usageOf(map) }, coverage: [] };
}

/** Summarize a whole snapshot. Analysis coverage follows each script's read coverage. */
export function summarizeSnapshot(snapshot: AccountSnapshot, options: SummarizeOptions = {}): AccountSummary {
  const summarized = snapshot.scripts.map((s) => summarizeScript(s, options));
  return {
    accountId: snapshot.accountId,
    scripts: summarized.map((s) => s.summary),
    namespaces: snapshot.namespaces,
    coverage: [...snapshot.coverage, ...summarized.flatMap((s) => s.coverage)],
  };
}

export const usageOf = (map: BindingMap): BindingUsage => ({
  used: [...map.used].sort(),
  envDestructured: map.envDestructured,
});

/** Rebuild the rules' `BindingMap` from a summary. Rules read only `used` and `envDestructured`. */
export const bindingMapOf = (usage: BindingUsage): BindingMap => ({
  refs: [],
  used: new Set(usage.used),
  envNames: new Set(),
  envDestructured: usage.envDestructured,
});
