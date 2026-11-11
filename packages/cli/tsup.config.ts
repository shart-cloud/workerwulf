import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  platform: "node",
  target: "node20",
  // Bundle our own source; keep runtime deps (oxc-parser has native/WASM
  // binaries) external so npm installs them rather than inlining.
  bundle: true,
  // @wulf/core and @wulf/analyze are private workspace packages: inline them.
  // Their own dependencies (effect, oxc-parser, smol-toml) stay external and
  // are declared in this package's dependencies.
  noExternal: ["@wulf/core", "@wulf/analyze"],
  clean: true,
  sourcemap: false,
  dts: false,
  // Preserve the executable shebang from src/index.ts.
  banner: { js: "#!/usr/bin/env node" },
});
