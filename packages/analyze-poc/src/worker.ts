import {
  analyzeAccount,
  auditProject,
  buildReport,
  memoryFiles,
  parse,
  parseWranglerText,
  toSerializable,
  type Severity,
  type SourceFile,
} from "@wulf/analyze";
import { AccountSnapshot } from "@wulf/core";
import * as Schema from "effect/Schema";

import { wasmMemoryBytes } from "./oxc-shim.worker.js";

interface Env {
  /** When set, every request needs `Authorization: Bearer <token>`. Unset under `wrangler dev`. */
  WULF_TOKEN?: string;
}

/** `wulf audit` for one project, sent as text. */
interface AnalyzeRequest {
  /** e.g. "wrangler.toml"; its extension selects TOML or JSON(C). */
  configPath: string;
  configText: string;
  /** Source files in scan order, paths as shown in findings. */
  sources: Array<{ path: string; text: string }>;
  /** Files next to the config for supply-chain rules (relative path → text; ancestors as "../"). */
  files?: Record<string, string>;
  severity?: Severity;
  ignore?: string[];
}

/** `wulf scan` over an already-collected account snapshot. */
interface ScanRequest {
  snapshot: unknown;
  /** Local source per deployed script name, for drift rules. */
  localSources?: Record<string, { path: string; text: string }>;
  severity?: Severity;
  ignore?: string[];
}

const decodeSnapshot = Schema.decodeUnknownSync(AccountSnapshot);

/** Reports carry a run id and timestamp like the CLI's; callers comparing output strip both. */
const report = (groups: Parameters<typeof buildReport>[2], coverage?: Parameters<typeof buildReport>[3]) =>
  toSerializable(buildReport(crypto.randomUUID(), new Date().toISOString(), groups, coverage));

async function authorized(request: Request, env: Env): Promise<boolean> {
  if (!env.WULF_TOKEN) return true;
  const enc = new TextEncoder();
  const got = enc.encode(request.headers.get("authorization") ?? "");
  const want = enc.encode(`Bearer ${env.WULF_TOKEN}`);
  return got.byteLength === want.byteLength && crypto.subtle.timingSafeEqual(got, want);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!(await authorized(request, env))) return new Response("unauthorized", { status: 401 });
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") return new Response("ok");
    if (request.method === "GET" && url.pathname === "/memory") {
      return Response.json({ wasmMemoryBytes: wasmMemoryBytes() });
    }
    if (request.method !== "POST") return new Response("not found", { status: 404 });

    if (url.pathname === "/analyze") {
      const input = (await request.json()) as AnalyzeRequest;
      const { config } = parseWranglerText(input.configPath, input.configText);
      const { groups, notes } = auditProject({
        configPath: input.configPath,
        config,
        sources: input.sources,
        ...(input.files && { files: memoryFiles(input.files) }),
        ignore: new Set(input.ignore ?? []),
        ...(input.severity && { severity: input.severity }),
      });
      return Response.json({ report: report(groups), notes });
    }

    if (url.pathname === "/scan") {
      const input = (await request.json()) as ScanRequest;
      let snapshot: AccountSnapshot;
      try {
        snapshot = decodeSnapshot(input.snapshot);
      } catch (err) {
        return Response.json({ error: `invalid snapshot: ${(err as Error).message}` }, { status: 400 });
      }
      const localSources = input.localSources
        ? new Map<string, SourceFile>(Object.entries(input.localSources).map(([name, f]) => [name, parse(f.path, f.text)]))
        : undefined;
      const analysis = analyzeAccount(snapshot, {
        ...(localSources && { localSources }),
        ignore: new Set(input.ignore ?? []),
        ...(input.severity && { severity: input.severity }),
      });
      const notes = analysis.errors.map((e) => `rule ${e.rule_id} errored: ${e.message}`);
      return Response.json({ report: report(analysis.groups, analysis.gaps), notes });
    }

    // Raw AST, for diffing against the native parser. `?summary=1` returns only
    // sizes and timings, for measuring large bundles.
    if (url.pathname === "/parse") {
      const { path, text } = (await request.json()) as { path: string; text: string };
      const started = Date.now();
      let source: SourceFile;
      try {
        source = parse(path, text);
      } catch (err) {
        return Response.json({ error: String(err), wasmMemoryBytes: wasmMemoryBytes() }, { status: 500 });
      }
      const ms = Date.now() - started;
      if (url.searchParams.get("summary") === "1") {
        const body = (source.ast["body"] as unknown[] | undefined) ?? [];
        return Response.json({
          bytes: text.length,
          statements: body.length,
          errors: source.errors.length,
          ms,
          wasmMemoryBytes: wasmMemoryBytes(),
        });
      }
      return Response.json({ program: source.ast, errors: source.errors, ms, wasmMemoryBytes: wasmMemoryBytes() });
    }

    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
