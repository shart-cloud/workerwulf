/**
 * Adapts @oxc-parser/wasm (0.40.1, wasm-bindgen web build) to the call shape the
 * CLI uses from the native "oxc-parser" package:
 *
 *   native: parseSync(filename, source, { sourceType, lang }) → { program, errors }
 *   wasm:   parseSync(source, { sourceType, sourceFilename })  → ParseResult (owns WASM memory)
 *
 * The WASM build infers the language from `sourceFilename`'s extension and panics
 * on an unknown one, so the CLI's `lang` is turned into a synthetic filename.
 *
 * Known difference: for JavaScript, 0.40.1's WASM build turns JSX on for every
 * extension (.js/.mjs/.cjs), so `program.sourceType.variant` reads "jsx" where the
 * native binding reports "standard". The rest of the AST and the diagnostics are
 * identical (test/ast-equivalence.test.ts), and no rule reads `sourceType`.
 */
export interface NativeParseOptions {
  sourceType?: "script" | "module";
  lang?: "js" | "jsx" | "ts" | "tsx";
}

const FILENAME_FOR_LANG: Record<NonNullable<NativeParseOptions["lang"]>, string> = {
  js: "input.js",
  jsx: "input.jsx",
  ts: "input.ts",
  tsx: "input.tsx",
};

export interface NativeShapeResult {
  program: unknown;
  errors: Array<{ message: string }>;
}

interface WasmParseResult {
  readonly program: unknown;
  readonly errors: Array<{ message: string }>;
  free(): void;
}

type WasmParseSync = (
  source: string,
  options?: { sourceType?: "script" | "module"; sourceFilename?: string },
) => WasmParseResult;

export const adaptWasmParser =
  (wasmParseSync: WasmParseSync) =>
  (_filename: string, source: string, options: NativeParseOptions = {}): NativeShapeResult => {
    const result = wasmParseSync(source, {
      sourceType: options.sourceType ?? "module",
      sourceFilename: FILENAME_FOR_LANG[options.lang ?? "js"],
    });
    try {
      return { program: result.program, errors: result.errors };
    } finally {
      result.free();
    }
  };
