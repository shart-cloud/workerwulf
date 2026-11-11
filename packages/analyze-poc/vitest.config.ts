import { defineConfig } from "vitest/config";

export default defineConfig({
  // workerd.test.ts starts `wrangler dev` and shells out to the real CLI.
  test: { testTimeout: 30_000, hookTimeout: 90_000 },
});
