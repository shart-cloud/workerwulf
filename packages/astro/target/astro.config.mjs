import { defineConfig } from "astro/config";
import cloudflare from "@astrojs/cloudflare";

// System-under-test for the @wulf/astro server-island probes.
export default defineConfig({
  output: "server",
  adapter: cloudflare(),
  security: {
    // Small limit so A-ISLAND-03 can exercise the 413 path cheaply.
    // Keep in sync with TARGET_LIMIT in src/probes/a-island-03.ts.
    serverIslandBodySizeLimit: 2048,
    // Small limit so A-ACTION-02 can exercise CONTENT_TOO_LARGE cheaply.
    // Keep in sync with TARGET_LIMIT in src/probes/a-action-02.ts.
    actionBodySizeLimit: 2048,
    checkOrigin: true,
  },
});
