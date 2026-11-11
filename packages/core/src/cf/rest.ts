import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schedule from "effect/Schedule";

import { CfApi, type RawBinding, type RawNamespace } from "./api.js";
import { ApiError, NotFound, PermissionDenied, RateLimited, type CfError } from "./errors.js";

export const DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4";

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface CfApiRestConfig {
  readonly accountId: string;
  readonly token: Redacted.Redacted<string>;
  readonly baseUrl?: string;
  /** Defaults to `globalThis.fetch`, so the layer runs on Node and in Workers. */
  readonly fetch?: FetchLike;
  /** Retries after the first attempt for 429s, 5xx and network errors. Default 3. */
  readonly retries?: number;
  /** First backoff delay; doubles each retry. Default 500 ms. */
  readonly retryBase?: Duration.Input;
}

interface CfEnvelope<T> {
  readonly result: T;
  readonly success: boolean;
  readonly errors?: ReadonlyArray<{ readonly message: string }>;
}

const isTransient = (e: CfError): boolean =>
  e._tag === "RateLimited" || (e._tag === "ApiError" && (e.status === undefined || e.status >= 500));

const classify = (path: string, res: Response): CfError | undefined => {
  if (res.ok) return undefined;
  if (res.status === 401 || res.status === 403) return new PermissionDenied({ path, status: res.status });
  if (res.status === 404) return new NotFound({ path });
  if (res.status === 429) return new RateLimited({ path });
  return new ApiError({ path, status: res.status, message: `${res.status} ${res.statusText}` });
};

/** Build the `CfApi` implementation over Cloudflare's REST API. */
export const makeCfApiRest = (config: CfApiRestConfig): CfApi["Service"] => {
  const baseUrl = config.baseUrl ?? DEFAULT_BASE_URL;
  const doFetch: FetchLike = config.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const acct = `/accounts/${encodeURIComponent(config.accountId)}`;
  const seg = encodeURIComponent;

  const retryPolicy = {
    schedule: Schedule.exponential(config.retryBase ?? Duration.millis(500)),
    times: config.retries ?? 3,
    while: isTransient,
  };

  /** One HTTP round trip, with retries for transient failures. */
  const send = (path: string, accept: string): Effect.Effect<Response, CfError> =>
    Effect.tryPromise({
      try: () =>
        doFetch(`${baseUrl}${path}`, {
          headers: { Authorization: `Bearer ${Redacted.value(config.token)}`, Accept: accept },
        }),
      catch: (cause) =>
        new ApiError({ path, message: cause instanceof Error ? cause.message : String(cause) }),
    }).pipe(
      Effect.flatMap((res) => {
        const err = classify(path, res);
        return err ? Effect.fail(err) : Effect.succeed(res);
      }),
      Effect.retry(retryPolicy),
    );

  const readBody = <A>(path: string, res: Response, read: (r: Response) => Promise<A>) =>
    Effect.tryPromise({
      try: () => read(res),
      catch: (cause) =>
        new ApiError({
          path,
          status: res.status,
          message: `unreadable body: ${cause instanceof Error ? cause.message : String(cause)}`,
        }),
    });

  const getJson = <T>(path: string): Effect.Effect<T, CfError> =>
    send(path, "application/json").pipe(
      Effect.flatMap((res) => readBody(path, res, (r) => r.json() as Promise<CfEnvelope<T>>)),
      Effect.flatMap((body) =>
        body.success === false
          ? Effect.fail(
              new ApiError({
                path,
                status: 200,
                message: body.errors?.map((e) => e.message).join("; ") || "success: false",
              }),
            )
          : Effect.succeed(body.result),
      ),
    );

  return {
    accountId: config.accountId,

    listScripts: getJson<ReadonlyArray<{ id: string }>>(`${acct}/workers/scripts`).pipe(
      Effect.map((scripts) => scripts.map((s) => s.id)),
    ),

    scriptBindings: (script) =>
      getJson<{ bindings?: ReadonlyArray<RawBinding> }>(
        `${acct}/workers/scripts/${seg(script)}/settings`,
      ).pipe(Effect.map((settings) => settings.bindings ?? [])),

    scriptContent: (script) => {
      const path = `${acct}/workers/scripts/${seg(script)}/content`;
      return send(path, "*/*").pipe(
        Effect.flatMap((res) =>
          readBody(path, res, async (r) => {
            const text = await r.text();
            const type = r.headers.get("content-type") ?? "";
            return type.includes("multipart/") ? extractModulesJs(text) : text;
          }),
        ),
      );
    },

    scriptRoutes: (script) =>
      getJson<ReadonlyArray<{ pattern?: string }> | null>(
        `${acct}/workers/scripts/${seg(script)}/routes`,
      ).pipe(
        Effect.map((routes) =>
          (routes ?? []).map((r) => r.pattern).filter((p): p is string => Boolean(p)),
        ),
      ),

    listNamespaces: getJson<ReadonlyArray<{ namespace_name?: string }> | null>(
      `${acct}/workers/dispatch/namespaces`,
    ).pipe(
      Effect.map((namespaces) =>
        (namespaces ?? []).map((n) => n.namespace_name).filter((n): n is string => Boolean(n)),
      ),
    ),

    namespace: (name) =>
      getJson<Record<string, unknown> | null>(`${acct}/workers/dispatch/namespaces/${seg(name)}`).pipe(
        Effect.map((ns): RawNamespace | undefined =>
          ns
            ? {
                name,
                trusted: ns["trusted_workers"] === true || ns["trusted"] === true,
                outbound: ns["outbound"],
                limits: ns["limits"],
              }
            : undefined,
        ),
      ),
  };
};

/** The `CfApi` service over Cloudflare's REST API. */
export const cfApiRest = (config: CfApiRestConfig): Layer.Layer<CfApi> =>
  Layer.succeed(CfApi, makeCfApiRest(config));

/**
 * Best-effort extraction of JS from a multipart module-worker content response:
 * strips part headers and joins the bodies. Enough for the binding map's env.X
 * scan across a bundle.
 */
export function extractModulesJs(multipart: string): string {
  const boundaryMatch = multipart.match(/^--(\S+)/m);
  if (!boundaryMatch) return multipart;
  const boundary = `--${boundaryMatch[1]}`;
  return multipart
    .split(boundary)
    .map((part) => {
      const sep = part.indexOf("\r\n\r\n");
      return sep >= 0 ? part.slice(sep + 4) : "";
    })
    .join("\n");
}
