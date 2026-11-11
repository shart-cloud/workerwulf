import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import { ApiError, NotFound, PermissionDenied, RateLimited, type CfError } from "./errors.js";

/** Raw binding entry from a script's settings. Values are never persisted. */
export interface RawBinding {
  readonly type: string;
  readonly name: string;
  readonly [key: string]: unknown;
}

/** Normalized dispatch-namespace data. */
export interface RawNamespace {
  readonly name: string;
  readonly trusted?: boolean;
  readonly outbound?: unknown;
  readonly limits?: unknown;
  readonly scripts?: ReadonlyArray<{ readonly name: string; readonly untrusted?: boolean }>;
}

/**
 * The Cloudflare API surface the platform reads. Every operation fails with a
 * typed `CfError`; callers decide what a failure means for coverage.
 */
export class CfApi extends Context.Service<
  CfApi,
  {
    readonly accountId: string;
    readonly listScripts: Effect.Effect<ReadonlyArray<string>, CfError>;
    readonly scriptBindings: (script: string) => Effect.Effect<ReadonlyArray<RawBinding>, CfError>;
    /** `undefined` when the script has no retrievable content. */
    readonly scriptContent: (script: string) => Effect.Effect<string | undefined, CfError>;
    readonly scriptRoutes: (script: string) => Effect.Effect<ReadonlyArray<string>, CfError>;
    readonly listNamespaces: Effect.Effect<ReadonlyArray<string>, CfError>;
    readonly namespace: (name: string) => Effect.Effect<RawNamespace | undefined, CfError>;
  }
>()("@wulf/core/CfApi") {}

/** A promise-shaped client, as `@wulf/cli`'s `CfClient` and its test fakes are. */
export interface PromiseCfClient {
  listScripts(): Promise<ReadonlyArray<string>>;
  getScriptBindings(script: string): Promise<ReadonlyArray<RawBinding>>;
  getScriptContent(script: string): Promise<string | undefined>;
  getRoutes(script: string): Promise<ReadonlyArray<string>>;
  listNamespaces(): Promise<ReadonlyArray<string>>;
  getNamespace(name: string): Promise<RawNamespace | undefined>;
}

const isCfError = (u: unknown): u is CfError =>
  u instanceof PermissionDenied ||
  u instanceof NotFound ||
  u instanceof RateLimited ||
  u instanceof ApiError;

const lift =
  (op: string) =>
  <A>(thunk: () => Promise<A>): Effect.Effect<A, CfError> =>
    Effect.tryPromise({
      try: thunk,
      catch: (cause) =>
        isCfError(cause)
          ? cause
          : new ApiError({ path: op, message: cause instanceof Error ? cause.message : String(cause) }),
    });

/**
 * Adapt a promise-shaped client into the `CfApi` service. A rejection that is
 * already a `CfError` keeps its tag; anything else becomes an `ApiError`.
 */
export const cfApiFromPromises = (accountId: string, client: PromiseCfClient): Layer.Layer<CfApi> =>
  Layer.succeed(CfApi, {
    accountId,
    listScripts: lift("listScripts")(() => client.listScripts()),
    scriptBindings: (s) => lift(`scriptBindings(${s})`)(() => client.getScriptBindings(s)),
    scriptContent: (s) => lift(`scriptContent(${s})`)(() => client.getScriptContent(s)),
    scriptRoutes: (s) => lift(`scriptRoutes(${s})`)(() => client.getRoutes(s)),
    listNamespaces: lift("listNamespaces")(() => client.listNamespaces()),
    namespace: (n) => lift(`namespace(${n})`)(() => client.getNamespace(n)),
  });
