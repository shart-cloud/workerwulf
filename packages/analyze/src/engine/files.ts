/**
 * The files around a wrangler config that config rules may read (package.json,
 * lockfiles, Dockerfiles, requirements.txt). Paths are POSIX and relative to
 * the config's directory, so rules never touch a filesystem: the CLI backs this
 * with disk reads, and a Worker with files sent in the request.
 */
export interface ProjectFiles {
  /** A file's text, or undefined if it doesn't exist or can't be read. */
  read(path: string): string | undefined;
  /** Whether any of `names` exists in the config's directory or one of its ancestors. */
  existsUp(names: readonly string[]): boolean;
  /** Every file under the config's directory, without descending into directories named in `skip`. */
  list(skip: ReadonlySet<string>): string[];
  /** How a path is shown in findings. */
  display(path: string): string;
}

/**
 * ProjectFiles over an in-memory map of relative path → text. Ancestor files
 * use `../` paths (`"../../pnpm-lock.yaml"`); `list` returns the other paths in
 * insertion order, and `display` returns paths unchanged.
 */
export function memoryFiles(files: Readonly<Record<string, string>>): ProjectFiles {
  const paths = Object.keys(files);
  return {
    read: (path) => (Object.hasOwn(files, path) ? files[path] : undefined),
    existsUp: (names) =>
      paths.some((p) => {
        const name = p.replace(/^(\.\.\/)+/, "");
        return names.includes(name) && /^(\.\.\/)*[^/]+$/.test(p);
      }),
    list: (skip) =>
      paths.filter((p) => {
        if (p.startsWith("../")) return false;
        const dirs = p.split("/").slice(0, -1);
        return !dirs.some((d) => skip.has(d));
      }),
    display: (path) => path,
  };
}
