import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  platform: "node",
  target: "node18",
  // Bundle our own source; keep runtime deps (oxc-parser has native/WASM
  // binaries) external so npm installs them rather than inlining.
  bundle: true,
  clean: true,
  sourcemap: false,
  dts: false,
  // Preserve the executable shebang from src/index.ts.
  banner: { js: "#!/usr/bin/env node" },
});
