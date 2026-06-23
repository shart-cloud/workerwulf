import { parseSync } from "oxc-parser";

/**
 * Loose structural node type. oxc-parser (0.40.x) emits its own native AST
 * (`@oxc-project/types`) — NOT the ESTree shape the PRD assumed. We treat nodes
 * structurally so the engine is resilient to AST drift and so rules don't depend
 * on the full oxc type surface. Every node has a `type` discriminant and byte
 * offsets; other fields are accessed defensively.
 *
 * Notable oxc node names that differ from ESTree (used by rules):
 *   - `StaticMemberExpression`   (ESTree: MemberExpression, computed=false)  → env.X
 *   - `ComputedMemberExpression` (ESTree: MemberExpression, computed=true)   → env["X"]
 *   - `Literal`                  (string/number/bool literals, has value+raw)
 *   - params live under `FormalParameters.items[].pattern`
 *   - function bodies are `FunctionBody` with a `statements` array
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
  /** Byte offset into the source text. */
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
