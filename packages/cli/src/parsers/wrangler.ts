import { readFileSync } from "node:fs";

import { parseWranglerText, type ParsedWrangler } from "@wulf/analyze";

export {
  parseWranglerText,
  resolveEnvironments,
  type BindingEntry,
  type ParsedWrangler,
  type ResolvedEnvironment,
  type WranglerConfig,
} from "@wulf/analyze";

/** Read and parse a wrangler.toml / wrangler.json / wrangler.jsonc from disk. */
export function parseWrangler(path: string): ParsedWrangler {
  return parseWranglerText(path, readFileSync(path, "utf8"));
}
