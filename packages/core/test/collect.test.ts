import * as Effect from "effect/Effect";
import { describe, expect, it } from "vitest";

import {
  cfApiFromPromises,
  collectAccount,
  isComplete,
  NotFound,
  PermissionDenied,
  type PromiseCfClient,
} from "../src/index.js";

const base: PromiseCfClient = {
  listScripts: async () => ["alpha", "beta"],
  getScriptBindings: async () => [{ type: "kv_namespace", name: "KV" }],
  getScriptContent: async (s) => `// ${s}`,
  getRoutes: async () => ["example.com/*"],
  listNamespaces: async () => ["tenants"],
  getNamespace: async (name) => ({ name, trusted: false }),
};

const run = (client: PromiseCfClient, options = {}) =>
  Effect.runPromise(collectAccount(options).pipe(Effect.provide(cfApiFromPromises("acct", client))));

describe("collectAccount", () => {
  it("collects every script and namespace with complete coverage", async () => {
    const snap = await run(base);
    expect(snap.accountId).toBe("acct");
    expect(snap.scripts.map((s) => s.name)).toEqual(["alpha", "beta"]);
    expect(snap.scripts[0]).toEqual({
      name: "alpha",
      bindings: [{ type: "kv_namespace", name: "KV" }],
      routes: ["example.com/*"],
      content: "// alpha",
    });
    expect(snap.namespaces).toEqual([{ name: "tenants", trusted: false }]);
    expect(snap.coverage.every((c) => c.status === "complete")).toBe(true);
    expect(isComplete(snap.coverage)).toBe(true);
  });

  it("records a denied read as coverage and leaves the field absent, not empty", async () => {
    const snap = await run({
      ...base,
      getScriptBindings: async (s) => {
        if (s === "beta") throw new PermissionDenied({ path: "/settings", status: 403 });
        return [];
      },
    });
    const beta = snap.scripts.find((s) => s.name === "beta")!;
    expect("bindings" in beta).toBe(false);
    expect(snap.coverage).toContainEqual({
      target: "script:beta",
      op: "bindings",
      status: "denied",
      detail: "HTTP 403 on /settings",
    });
    // A permission gap is an expected gap, not a failed scan.
    expect(isComplete(snap.coverage)).toBe(true);
  });

  it("marks a missing endpoint unavailable and an unknown error failed", async () => {
    const snap = await run({
      ...base,
      getRoutes: async () => {
        throw new NotFound({ path: "/routes" });
      },
      listNamespaces: async () => {
        throw new Error("socket hang up");
      },
    });
    expect(snap.coverage.filter((c) => c.op === "routes").map((c) => c.status)).toEqual([
      "unavailable",
      "unavailable",
    ]);
    expect(snap.coverage).toContainEqual(
      expect.objectContaining({ op: "listNamespaces", status: "failed" }),
    );
    expect(snap.namespaces).toEqual([]);
    expect(isComplete(snap.coverage)).toBe(false);
  });

  it("fails the collection when scripts can't be listed", async () => {
    const exit = Effect.runPromise(
      Effect.flip(
        collectAccount().pipe(
          Effect.provide(
            cfApiFromPromises("acct", {
              ...base,
              listScripts: async () => {
                throw new PermissionDenied({ path: "/scripts", status: 403 });
              },
            }),
          ),
        ),
      ),
    );
    expect((await exit)._tag).toBe("PermissionDenied");
  });

  it("inspects only the requested namespace without listing", async () => {
    let listed = false;
    const snap = await run(
      {
        ...base,
        listNamespaces: async () => {
          listed = true;
          return [];
        },
      },
      { namespace: "only" },
    );
    expect(listed).toBe(false);
    expect(snap.namespaces.map((n) => n.name)).toEqual(["only"]);
  });

  it("keeps script and coverage order stable under concurrency", async () => {
    const names = Array.from({ length: 12 }, (_, i) => `s${i}`);
    const snap = await run({
      ...base,
      listScripts: async () => names,
      getScriptContent: async (s) => {
        await new Promise((r) => setTimeout(r, Math.random() * 5));
        return s;
      },
    });
    expect(snap.scripts.map((s) => s.name)).toEqual(names);
    expect(
      snap.coverage.filter((c) => c.op === "content").map((c) => c.target),
    ).toEqual(names.map((n) => `script:${n}`));
  });
});
