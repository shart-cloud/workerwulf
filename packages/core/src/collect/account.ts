import * as Effect from "effect/Effect";

import { CfApi, type RawBinding, type RawNamespace } from "../cf/api.js";
import type { CfError } from "../cf/errors.js";
import { coverageFromError, type Coverage } from "./coverage.js";

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

/**
 * Collect the Workers surface of an account. Only listing the scripts is fatal:
 * without it there is nothing to scan. Every other read degrades to a coverage
 * entry so the rules still run on what could be seen.
 */
export const collectAccount = (
  options: CollectAccountOptions = {},
): Effect.Effect<AccountSnapshot, CfError, CfApi> =>
  Effect.gen(function* () {
    const api = yield* CfApi;
    const coverage: Coverage[] = [];

    const names = yield* api.listScripts;
    coverage.push({ target: "account", op: "listScripts", status: "complete" });

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
    const scripts = collected.map((c) => c.script);
    for (const c of collected) coverage.push(...c.coverage);

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

    return { accountId: api.accountId, scripts, namespaces, coverage };
  });
