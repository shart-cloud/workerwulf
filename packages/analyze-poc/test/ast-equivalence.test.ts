import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

// oxc-parser's workerd WASM build (the one the Worker runs) vs its native Node binding.
import { parseSync as wasmParse } from "../src/oxc-shim.node.js";
import { firstDiff, langOf, nativeParse, normalize, packagesDir, rel, sourceFiles } from "./helpers.js";

const require = createRequire(import.meta.url);

// Every TS/JS source in the monorepo (probe Workers, CLI, rules, fixtures), plus
// large real-world JS bundles from Effect, which exercise far more syntax.
const corpus = [
  ...sourceFiles(packagesDir),
  require.resolve("effect/Schema", { paths: [`${packagesDir}/core`] }),
  require.resolve("effect/Effect", { paths: [`${packagesDir}/core`] }),
];

describe("oxc WASM vs native AST", () => {
  it(`produces identical ASTs across ${corpus.length} files`, () => {
    const mismatches: string[] = [];
    let bytes = 0;
    for (const file of corpus) {
      const text = readFileSync(file, "utf8");
      bytes += text.length;
      const a = nativeParse(file, text);
      const b = wasmParse(file, text, { sourceType: "module", lang: langOf(file) });
      if (JSON.stringify(a.errors) !== JSON.stringify(b.errors)) {
        mismatches.push(`${rel(file)} errors differ`);
        continue;
      }
      const diff =
        firstDiff(normalize(a.program), normalize(b.program)) ??
        (a.errors.length !== b.errors.length ? `errors: ${a.errors.length} vs ${b.errors.length}` : undefined);
      if (diff) mismatches.push(`${rel(file)} ${diff}`);
    }
    console.log(`compared ${corpus.length} files, ${(bytes / 1024).toFixed(0)} KiB`);
    expect(mismatches).toEqual([]);
  });
});
