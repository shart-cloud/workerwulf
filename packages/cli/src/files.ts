import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

import type { ProjectFiles } from "@wulf/analyze";

/** ProjectFiles on disk, rooted at a config's directory. Findings show paths relative to the cwd. */
export function diskFiles(configPath: string): ProjectFiles {
  const root = dirname(resolve(configPath));
  return {
    read(path) {
      try {
        return readFileSync(join(root, path), "utf8");
      } catch {
        return undefined;
      }
    },
    existsUp(names) {
      let cur = root;
      while (true) {
        if (names.some((name) => existsSync(join(cur, name)))) return true;
        const parent = dirname(cur);
        if (parent === cur) return false;
        cur = parent;
      }
    },
    list(skip) {
      const out: string[] = [];
      const walk = (rel: string): void => {
        const dir = join(root, rel);
        if (!existsSync(dir)) return;
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          const path = rel ? `${rel}/${entry.name}` : entry.name;
          if (entry.isDirectory()) {
            if (!skip.has(entry.name)) walk(path);
          } else if (entry.isFile()) {
            out.push(path);
          }
        }
      };
      walk("");
      return out;
    },
    display(path) {
      const abs = join(root, path);
      return relative(process.cwd(), abs) || abs;
    },
  };
}
