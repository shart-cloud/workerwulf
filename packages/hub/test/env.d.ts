import type { Env as HubEnv } from "../src/env.js";

declare global {
  namespace Cloudflare {
    interface Env extends HubEnv {}
    interface GlobalProps {
      mainModule: typeof import("../src/index.js");
      durableNamespaces: "ScanHub";
    }
  }
}
