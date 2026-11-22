import { isMemberAccess, objectLiteralProperties } from "../../ast/nodes.js";
import type { AstNode } from "../../ast/parse.js";
import { calleeMemberPath } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import { enabledWorkersCaches } from "../config/workers-cache.js";
import {
  callArgs,
  literalString,
  makeFinding,
  propKeyName,
  propValue,
  scanAst,
} from "./_utils.js";

/**
 * Custom identity/auth headers that are NOT part of the Workers Cache key and
 * do NOT trigger Cloudflare's inbound `Authorization` auto-bypass (W-WC-04 / W-WC-05).
 */
const UNKEYED_IDENTITY_HEADER_RE =
  /^(?:x-user(?:-id)?|x-tenant(?:-id)?|x-account(?:-id)?|x-caller(?:-id)?|x-identity|x-api-key|x-auth-[a-z0-9-]+|x-session-[a-z0-9-]+|x-forwarded-user)$/i;

/**
 * WF-WC-02 — Wave 5 (W-WC-02). `ctx.cache.purge({ purgeEverything: true })`
 * evicts the entire entrypoint cache and draws from the account's shared zone
 * purge rate-limit budget (availability / origin-load amplification DoS).
 */
registerSource({
  id: "WF-WC-02",
  title: "Workers Cache purgeEverything() callable from Worker code",
  severity: "high",
  probe: "W-WC-02",
  family: "F",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (!path || path[path.length - 1] !== "purge") continue;
      const receiver = path.slice(0, -1).join(".");
      if (receiver !== "ctx.cache" && receiver !== "cache" && !receiver.endsWith(".cache")) continue;
      const arg = callArgs(node)[0];
      if (!arg || arg.type !== "ObjectExpression") continue;
      const hasPurgeEverything = objectLiteralProperties(arg).some((p) => {
        if (propKeyName(p) !== "purgeEverything") return false;
        const v = propValue(p);
        return v?.type === "Literal" && v["value"] === true;
      });
      if (!hasPurgeEverything) continue;
      findings.push(
        makeFinding(
          ctx.source,
          node,
          this,
          "`cache.purge({ purgeEverything: true })` evicts every cached response for this entrypoint " +
            "and consumes the shared Cloudflare zone purge rate limit (W-WC-02). If reachable from " +
            "untrusted callers or injected code, it forces origin load amplification and can starve legitimate purges.",
          "Prefer targeted tag or prefix purges (`{ tags: [...] }` / `{ prefixes: [...] }`) and gate any " +
            "`purgeEverything` path behind strong operator authentication and strict rate limits.",
        ),
      );
    }
    return findings;
  },
});

/**
 * WF-WC-03 — Wave 5 (W-WC-05 arm C). Stripping `Set-Cookie` from responses on a
 * Worker with declarative Workers Cache enabled defeats the platform's response-side
 * `Set-Cookie` cache auto-bypass (unlike `Authorization`, which is decided inbound).
 */
registerSource({
  id: "WF-WC-03",
  title: "Response strips Set-Cookie while declarative Workers Cache is enabled",
  severity: "high",
  probe: "W-WC-05",
  family: "C",
  check(ctx) {
    if (enabledWorkersCaches(ctx.config).length === 0) return [];
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (!path || path[path.length - 1] !== "delete") continue;
      const receiver = path.slice(0, -1).join(".").toLowerCase();
      if (!receiver.includes("header")) continue;
      const headerName = literalString(callArgs(node)[0]);
      if (!headerName || headerName.toLowerCase() !== "set-cookie") continue;
      findings.push(
        makeFinding(
          ctx.source,
          node,
          this,
          "Worker deletes the `Set-Cookie` header while declarative Workers Cache is enabled. " +
            "W-WC-05 proved that `Set-Cookie` auto-bypass is evaluated response-side — stripping it " +
            "allows per-user responses without `Cache-Control: private, no-store` to be cached via " +
            "RFC 9111 heuristics and replayed to other callers.",
          "Do not strip `Set-Cookie` from per-user responses on cached entrypoints, and explicitly set " +
            "`Cache-Control: private, no-store` on every personalized response.",
        ),
      );
    }
    return findings;
  },
});

/**
 * WF-WC-04 — Wave 5 (W-WC-04). Reading a custom identity/auth header on a Worker
 * with declarative Workers Cache enabled and no `ctx.props` keying in the file.
 */
registerSource({
  id: "WF-WC-04",
  title: "Unkeyed custom identity header read on a Workers-Cache-enabled Worker",
  severity: "critical",
  probe: "W-WC-04",
  family: "C",
  check(ctx) {
    if (enabledWorkersCaches(ctx.config).length === 0) return [];
    // If the file references `ctx.props` (or `this.ctx.props`), assume identity keying
    // is handled through props (W-WC-04 control arm).
    let usesCtxProps = false;
    scanAst(ctx.source.ast, (node) => {
      if (usesCtxProps || !isMemberAccess(node)) return;
      const prop = node["property"] as AstNode | undefined;
      if (prop?.type !== "Identifier" || prop["name"] !== "props") return;
      const obj = node["object"] as AstNode | undefined;
      if (obj?.type === "Identifier" && obj["name"] === "ctx") {
        usesCtxProps = true;
      } else if (obj && isMemberAccess(obj)) {
        const inner = obj["property"] as AstNode | undefined;
        if (inner?.type === "Identifier" && inner["name"] === "ctx") usesCtxProps = true;
      }
    });
    if (usesCtxProps) return [];

    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (!path || path[path.length - 1] !== "get") continue;
      const receiver = path.slice(0, -1).join(".").toLowerCase();
      if (!receiver.includes("header")) continue;
      const headerName = literalString(callArgs(node)[0]);
      if (!headerName || !UNKEYED_IDENTITY_HEADER_RE.test(headerName)) continue;
      findings.push(
        makeFinding(
          ctx.source,
          node,
          this,
          `Custom identity header "${headerName}" is read while declarative Workers Cache is enabled ` +
            "without `ctx.props` keying. W-WC-04 demonstrated that custom auth/identity headers are not " +
            "part of the Workers Cache key — caller B receives caller A's cached response.",
          "Move caller identity into `ctx.props` (via a gateway Worker / service binding) so it enters " +
            "the cache key, or disable caching / return `Cache-Control: private, no-store` for this route.",
        ),
      );
    }
    return findings;
  },
});
