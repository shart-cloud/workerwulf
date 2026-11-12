import { fileURLToPath } from "node:url";

import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          CLOUDFLARE_ACCOUNT_ID: "acct-test",
          CLOUDFLARE_API_TOKEN: "cf-test-token",
          WULF_TOKEN: "hub-test-token",
          KEEP_SCANS: "2",
        },
        serviceBindings: { CF_API: "fake-cf" },
        workers: [{ name: "fake-cf", modules: true, scriptPath: "./test/fake-cf.js" }],
      },
    }),
  ],
  // wrangler.jsonc's `alias` doesn't reach Vite: point "oxc-parser" at the workerd WASM shim here too.
  resolve: { alias: [{ find: /^oxc-parser$/, replacement: fileURLToPath(new URL("./src/oxc-shim.worker.ts", import.meta.url)) }] },
  test: { testTimeout: 30_000 },
});
