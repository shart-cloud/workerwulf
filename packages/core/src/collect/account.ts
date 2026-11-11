import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

import { CfApi, type RawBinding, type RawNamespace } from "../cf/api.js";
import type { CfError } from "../cf/errors.js";
import { Coverage, coverageFromError } from "./coverage.js";

/**
 * One deployed script as collected. A field is `undefined` when its read did
 * not complete; the matching `Coverage` entry says why. Never an empty stand-in.
 */
export interface ScriptSnapshot {
  readonly name: string;
  readonly bindings?: ReadonlyArray<RawBinding>;
  readonly routes?: ReadonlyArray<string>;
  /** Downloaded bundle text. Analysed in memory; not persisted. */
  readonly content?: string;
}

export interface AccountSnapshot {
  readonly accountId: string;
  readonly scripts: ReadonlyArray<ScriptSnapshot>;
  readonly namespaces: ReadonlyArray<RawNamespace>;
  readonly coverage: ReadonlyArray<Coverage>;
}

/**
 * Decodes a snapshot that crossed a process boundary (e.g. posted to a Worker).
 * Binding entries keep only `type` and `name`, which is all the rules read, so
 * binding values are dropped at the edge.
 */
export const AccountSnapshot = Schema.Struct({
  accountId: Schema.String,
  scripts: Schema.Array(
    Schema.Struct({
      name: Schema.String,
      bindings: Schema.optionalKey(Schema.Array(Schema.Struct({ type: Schema.String, name: Schema.String }))),
      routes: Schema.optionalKey(Schema.Array(Schema.String)),
      content: Schema.optionalKey(Schema.String),
    }),
  ),
  namespaces: Schema.Array(
    Schema.Struct({
      name: Schema.String,
      trusted: Schema.optionalKey(Schema.Boolean),
      outbound: Schema.optionalKey(Schema.Unknown),
      limits: Schema.optionalKey(Schema.Unknown),
      scripts: Schema.optionalKey(
        Schema.Array(Schema.Struct({ name: Schema.String, untrusted: Schema.optionalKey(Schema.Boolean) })),
      ),
    }),
  ),
  coverage: Schema.Array(Coverage),
});

export interface CollectAccountOptions {
  /** Inspect only this dispatch namespace instead of listing them all. */
  readonly namespace?: string;
  /** Scripts fetched in parallel. Each script costs three requests. Default 4. */
  readonly concurrency?: number;
}

interface Attempt<A> {
  readonly value: A | undefined;
  readonly coverage: Coverage;
}

/** Run one read, turning its failure into a coverage entry instead of an error. */
const attempt = <A>(
  target: string,
  op: string,
  read: Effect.Effect<A, CfError>,
): Effect.Effect<Attempt<A>> =>
  read.pipe(
    Effect.match({
      onSuccess: (value) => ({ value, coverage: { target, op, status: "complete" as const } }),
      onFailure: (error) => ({ value: undefined, coverage: coverageFromError(target, op, error) }),
    }),
  );

/** Scripts and namespaces collected so far, with the coverage of every read. */
export interface CollectedPart {
  readonly scripts: ReadonlyArray<ScriptSnapshot>;
  readonly namespaces: ReadonlyArray<RawNamespace>;
  readonly coverage: ReadonlyArray<Coverage>;
}

/** List the account's scripts. Fatal on failure: without the list there is nothing to scan. */
export const collectScriptNames: Effect.Effect<ReadonlyArray<string>, CfError, CfApi> = Effect.gen(
  function* () {
    const api = yield* CfApi;
    return yield* api.listScripts;
  },
);

export const LIST_SCRIPTS_COVERAGE: Coverage = { target: "account", op: "listScripts", status: "complete" };

/**
 * Read bindings, routes and content for some scripts. Never fails: each read
 * that doesn't complete becomes a coverage entry. Output keeps input order.
 */
export const collectScripts = (
  names: ReadonlyArray<string>,
  options: Pick<CollectAccountOptions, "concurrency"> = {},
): Effect.Effect<CollectedPart, never, CfApi> =>
  Effect.gen(function* () {
    const api = yield* CfApi;
    const collected = yield* Effect.forEach(
      names,
      (name) =>
        Effect.gen(function* () {
          const target = `script:${name}`;
          const [bindings, routes, content] = yield* Effect.all(
            [
              attempt(target, "bindings", api.scriptBindings(name)),
              attempt(target, "routes", api.scriptRoutes(name)),
              attempt(target, "content", api.scriptContent(name)),
            ],
            { concurrency: "unbounded" },
          );
          const script: ScriptSnapshot = {
            name,
            ...(bindings.value !== undefined && { bindings: bindings.value }),
            ...(routes.value !== undefined && { routes: routes.value }),
            ...(content.value !== undefined && { content: content.value }),
          };
          return { script, coverage: [bindings.coverage, routes.coverage, content.coverage] };
        }),
      { concurrency: options.concurrency ?? 4 },
    );
    // forEach keeps input order, so coverage stays deterministic under concurrency.
    return {
      scripts: collected.map((c) => c.script),
      namespaces: [],
      coverage: collected.flatMap((c) => c.coverage),
    };
  });

/** Read dispatch namespaces (one, or all of them). Never fails; gaps become coverage. */
export const collectNamespaces = (
  options: Pick<CollectAccountOptions, "namespace"> = {},
): Effect.Effect<CollectedPart, never, CfApi> =>
  Effect.gen(function* () {
    const api = yield* CfApi;
    const coverage: Coverage[] = [];
    let namespaceNames: ReadonlyArray<string>;
    if (options.namespace !== undefined) {
      namespaceNames = [options.namespace];
    } else {
      const listed = yield* attempt("account", "listNamespaces", api.listNamespaces);
      coverage.push(listed.coverage);
      namespaceNames = listed.value ?? [];
    }

    const namespaces: RawNamespace[] = [];
    for (const name of namespaceNames) {
      const read = yield* attempt(`namespace:${name}`, "namespace", api.namespace(name));
      coverage.push(read.coverage);
      if (read.value) namespaces.push(read.value);
    }
    return { scripts: [], namespaces, coverage };
  });

/** Join parts in collection order into one snapshot. */
export const joinParts = (accountId: string, parts: ReadonlyArray<CollectedPart>): AccountSnapshot => ({
  accountId,
  scripts: parts.flatMap((p) => p.scripts),
  namespaces: parts.flatMap((p) => p.namespaces),
  coverage: parts.flatMap((p) => p.coverage),
});

/**
 * Collect the Workers surface of an account. Only listing the scripts is fatal:
 * without it there is nothing to scan. Every other read degrades to a coverage
 * entry so the rules still run on what could be seen.
 *
 * ScanWorkflow runs the same pieces one step at a time: the list, scripts in
 * chunks, then namespaces.
 */
export const collectAccount = (
  options: CollectAccountOptions = {},
): Effect.Effect<AccountSnapshot, CfError, CfApi> =>
  Effect.gen(function* () {
    const api = yield* CfApi;
    const names = yield* collectScriptNames;
    const scripts = yield* collectScripts(names, options);
    const namespaces = yield* collectNamespaces(options);
    const listed: CollectedPart = { scripts: [], namespaces: [], coverage: [LIST_SCRIPTS_COVERAGE] };
    return joinParts(api.accountId, [listed, scripts, namespaces]);
  });
