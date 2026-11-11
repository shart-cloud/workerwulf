import { parseSync } from "oxc-parser";

/**
 * Loose structural node type. oxc-parser emits an ESTree-compatible AST (with
 * TypeScript extensions, as typescript-eslint does). We treat nodes structurally,
 * so rules don't depend on the full oxc type surface: every node has a `type`
 * discriminant and `start`/`end` offsets, and other fields are read defensively.
 *
 * Offsets are UTF-16 code-unit indices, so they index `SourceFile.text` directly.
 * (oxc 0.40 reported UTF-8 byte offsets, which misplaced every location after a
 * non-ASCII character.)
 *
 * Node-shape details live in `nodes.ts`; rules should use its predicates
 * (`isStaticMember`, `isObjectLiteralProperty`, `functionParams`, ...) rather
 * than matching node types directly.
 */
export interface AstNode {
  type: string;
  start: number;
  end: number;
  [key: string]: unknown;
}

export interface SourceLocation {
  /** 1-based line number. */
  line: number;
  /** 1-based column number. */
  column: number;
  /** UTF-16 offset into the source text. */
  offset: number;
}

export interface SourceFile {
  /** Path relative to the scan root (used in finding `resource` strings). */
  path: string;
  /** Raw source text. */
  text: string;
  /** Root Program node of the oxc AST. */
  ast: AstNode;
  /** Parse diagnostics. Non-fatal — a partial AST is still returned. */
  errors: string[];
  /** Precomputed line-start offsets for offset→{line,column} conversion. */
  lineStarts: number[];
}

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) starts.push(i + 1);
  }
  return starts;
}

/**
 * Parse a JavaScript/TypeScript source file into an oxc AST.
 *
 * Parse errors are non-fatal: Workers source is sometimes unconventional
 * (Wasm imports, exotic syntax) and oxc returns a usable partial AST. We surface
 * the error messages on `SourceFile.errors` for diagnostics but keep scanning.
 */
export function parse(path: string, text: string): SourceFile {
  const lang = path.endsWith(".ts")
    ? "ts"
    : path.endsWith(".tsx")
      ? "tsx"
      : path.endsWith(".jsx")
        ? "jsx"
        : "js";
  const result = parseSync(path, text, { sourceType: "module", lang });
  const errors = result.errors.map((e) => e.message ?? String(e));
  return {
    path,
    text,
    ast: result.program as unknown as AstNode,
    errors,
    lineStarts: computeLineStarts(text),
  };
}

/** Convert a byte offset into a 1-based line/column location. */
export function locAt(source: SourceFile, offset: number): SourceLocation {
  const { lineStarts } = source;
  // Binary search for the greatest lineStart <= offset.
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - lineStarts[lo]! + 1, offset };
}
