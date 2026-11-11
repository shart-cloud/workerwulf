import { describe, expect, it } from "vitest";

import { parseWranglerText } from "../src/index.js";

describe("wrangler.jsonc", () => {
  it("accepts comments and trailing commas, and leaves strings alone", () => {
    const { config } = parseWranglerText(
      "wrangler.jsonc",
      `{
        // comment
        "name": "x", /* block */
        "main": "src/index.ts",
        "vars": { "A": "keep, } and // and ,]", },
        "kv_namespaces": [ { "binding": "KV", "id": "1", }, ],
      }`,
    );
    expect(config.name).toBe("x");
    expect(config.vars).toEqual({ A: "keep, } and // and ,]" });
    expect(config.kv_namespaces).toEqual([{ binding: "KV", id: "1" }]);
  });
});
