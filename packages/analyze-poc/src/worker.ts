import { parse } from "@wulf/cli/src/ast/parse.js";

import { analyzeProject, type AnalyzeInput } from "./analyze.js";

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return new Response("ok");
    if (request.method !== "POST") return new Response("not found", { status: 404 });

    if (url.pathname === "/analyze") {
      const input = (await request.json()) as AnalyzeInput;
      return Response.json(analyzeProject(input));
    }

    // Raw AST, for diffing against the native parser.
    if (url.pathname === "/parse") {
      const { path, text } = (await request.json()) as { path: string; text: string };
      const started = Date.now();
      const source = parse(path, text);
      return Response.json({ program: source.ast, errors: source.errors, ms: Date.now() - started });
    }

    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler;
