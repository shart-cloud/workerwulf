import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Redacted from "effect/Redacted";
import { describe, expect, it } from "vitest";

import { makeCfApiRest, type FetchLike } from "../src/index.js";

const BASE = "https://cf.test/client/v4";

interface Call {
  url: string;
  auth: string | null;
}

/** Route table: path suffix → successive responses (last one repeats). */
function fakeFetch(routes: Record<string, Array<() => Response>>): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const seen = new Map<string, number>();
  const fetch: FetchLike = async (url, init) => {
    const headers = new Headers(init?.headers);
    calls.push({ url, auth: headers.get("authorization") });
    const path = url.slice(BASE.length);
    const responses = routes[path];
    if (!responses) return new Response("no route", { status: 599 });
    const n = seen.get(path) ?? 0;
    seen.set(path, n + 1);
    return responses[Math.min(n, responses.length - 1)]!();
  };
  return { fetch, calls };
}

const ok = (result: unknown) => () => Response.json({ success: true, result });
const status = (code: number) => () => new Response("x", { status: code });

const api = (fetch: FetchLike) =>
  makeCfApiRest({
    accountId: "acct",
    token: Redacted.make("tkn"),
    baseUrl: BASE,
    fetch,
    retryBase: Duration.millis(1),
  });

const failureText = async (eff: Effect.Effect<unknown, { _tag: string }>) => {
  const exit = await Effect.runPromiseExit(eff);
  if (Exit.isSuccess(exit)) throw new Error("expected failure");
  const err = exit.cause.toString();
  return err;
};

describe("CfApiRest", () => {
  it("lists scripts and sends the bearer token", async () => {
    const { fetch, calls } = fakeFetch({
      "/accounts/acct/workers/scripts": [ok([{ id: "a" }, { id: "b" }])],
    });
    expect(await Effect.runPromise(api(fetch).listScripts)).toEqual(["a", "b"]);
    expect(calls[0]!.auth).toBe("Bearer tkn");
  });

  it("URL-encodes script names in paths", async () => {
    const { fetch, calls } = fakeFetch({
      "/accounts/acct/workers/scripts/a%2Fb%3Fx/settings": [ok({ bindings: [{ type: "kv_namespace", name: "KV" }] })],
    });
    const bindings = await Effect.runPromise(api(fetch).scriptBindings("a/b?x"));
    expect(bindings).toEqual([{ type: "kv_namespace", name: "KV" }]);
    expect(calls[0]!.url).toContain("a%2Fb%3Fx");
  });

  it("maps 403 to PermissionDenied without retrying", async () => {
    const { fetch, calls } = fakeFetch({ "/accounts/acct/workers/scripts/s/settings": [status(403)] });
    const err = await Effect.runPromise(Effect.flip(api(fetch).scriptBindings("s")));
    expect(err._tag).toBe("PermissionDenied");
    expect(calls).toHaveLength(1);
  });

  it("maps 404 to NotFound", async () => {
    const { fetch } = fakeFetch({ "/accounts/acct/workers/scripts/s/routes": [status(404)] });
    const err = await Effect.runPromise(Effect.flip(api(fetch).scriptRoutes("s")));
    expect(err._tag).toBe("NotFound");
  });

  it("retries 429 and 5xx, then succeeds", async () => {
    const { fetch, calls } = fakeFetch({
      "/accounts/acct/workers/scripts": [status(429), status(503), ok([{ id: "a" }])],
    });
    expect(await Effect.runPromise(api(fetch).listScripts)).toEqual(["a"]);
    expect(calls).toHaveLength(3);
  });

  it("gives up after the retry budget with the last error", async () => {
    const { fetch, calls } = fakeFetch({ "/accounts/acct/workers/scripts": [status(500)] });
    const err = await Effect.runPromise(Effect.flip(api(fetch).listScripts));
    expect(err._tag).toBe("ApiError");
    expect(calls).toHaveLength(4); // first attempt + 3 retries
  });

  it("treats success:false as a non-retryable ApiError", async () => {
    const { fetch, calls } = fakeFetch({
      "/accounts/acct/workers/scripts": [
        () => Response.json({ success: false, errors: [{ message: "nope" }], result: null }),
      ],
    });
    const err = await Effect.runPromise(Effect.flip(api(fetch).listScripts));
    expect(err).toMatchObject({ _tag: "ApiError", message: "nope" });
    expect(calls).toHaveLength(1);
  });

  it("extracts JS from multipart script content", async () => {
    const body = '--b1\r\nContent-Disposition: form-data; name="index.js"\r\n\r\nexport default {};\r\n--b1--';
    const { fetch } = fakeFetch({
      "/accounts/acct/workers/scripts/s/content": [
        () => new Response(body, { headers: { "content-type": "multipart/form-data; boundary=b1" } }),
      ],
    });
    const content = await Effect.runPromise(api(fetch).scriptContent("s"));
    expect(content).toContain("export default {};");
    expect(content).not.toContain("Content-Disposition");
  });

  it("normalizes a dispatch namespace", async () => {
    const { fetch } = fakeFetch({
      "/accounts/acct/workers/dispatch/namespaces/t": [ok({ trusted_workers: true, outbound: { worker: "o" } })],
    });
    expect(await Effect.runPromise(api(fetch).namespace("t"))).toEqual({
      name: "t",
      trusted: true,
      outbound: { worker: "o" },
      limits: undefined,
    });
  });

  it("never puts the token in error messages", async () => {
    const { fetch } = fakeFetch({ "/accounts/acct/workers/scripts": [status(403)] });
    expect(await failureText(api(fetch).listScripts)).not.toContain("tkn");
  });
});
