import { objectLiteralProperties } from "../../ast/nodes.js";
import type { AstNode } from "../../ast/parse.js";
import { calleeMemberPath, findEnvAccess } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import { bindingNamesOfType } from "../../parsers/bindings.js";
import {
  callArgs,
  literalNumber,
  literalString,
  makeFinding,
  propKeyName,
  propValue,
} from "./_utils.js";

const RIVET_TOKEN_RE = /\brivet_token\.[A-Za-z0-9._-]{8,}/;
const RIVET_DEFAULT_ADMIN_RE = /^Bearer\s+default$/i;
const RIVET_AUTH_URL_RE = /^https?:\/\/[^/\s:@]+:[^/\s@]+@[^\s/]*rivet[^\s/]*/i;
const SENSITIVE_MOUNT_RE = /(?:^|\/)(?:\.git|\.env(?:\.[^/]*)?|\.dev\.vars|\.open-orange|\.rivet|secrets?)(?:\/|$)/i;
const ACTOR_AUTH_HOOKS = new Set(["onAuth", "onBeforeConnect", "createConnState"]);

/**
 * WF-RIVET-03 — Hardcoded Rivet token (`rivet_token.*`), local Engine default
 * admin bearer (`Bearer default`), or credential-bearing Rivet endpoint URL.
 */
registerSource({
  id: "WF-RIVET-03",
  title: "Hardcoded Rivet token or Engine credential in source",
  severity: "critical",
  probe: "W-CAP-02",
  family: "A",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "Literal")) {
      const value = literalString(node);
      if (!value) continue;
      let detail: string | undefined;
      if (RIVET_TOKEN_RE.test(value)) {
        detail = "a Rivet token (`rivet_token.*`)";
      } else if (RIVET_DEFAULT_ADMIN_RE.test(value.trim())) {
        detail = 'the local Rivet Engine default admin token (`Bearer default`)';
      } else if (RIVET_AUTH_URL_RE.test(value)) {
        detail = "a credential-bearing Rivet endpoint URL (`https://namespace:token@...`)";
      }
      if (!detail) continue;
      findings.push(
        makeFinding(
          ctx.source,
          node,
          this,
          `Source contains ${detail}. Anyone with a Rivet token carrying an \`actor_gateway\` grant ` +
            "can invoke OpenOrange Durable Objects, KV, D1, and Queue actors directly through the " +
            "Rivet Engine gateway (bypassing the Worker and spoofing `request.cf`).",
          "Read Rivet credentials from runtime secrets (env / `--secrets-file`), never hardcode " +
            "tokens or `Bearer default`, and mint least-privilege tokens without `actor_gateway` for " +
            "clients that should not bypass the Worker.",
        ),
      );
    }
    return findings;
  },
});

/**
 * WF-RIVET-04 — Dynamic Worker loader pitfalls across Cloudflare + OpenOrange:
 *  (a) `limits: { subRequests: 0 }` — silently grants 50 subrequests on
 *      Cloudflare production (F-1) and is ignored on OSS workerd & OpenOrange.
 *  (b) `mounts` with broad (`.`, `/`, `..`) or secret-bearing `hostPath` in
 *      OpenOrange agentOS VMs.
 */
registerSource({
  id: "WF-RIVET-04",
  title: "Dynamic Worker loader relies on ignored/broken limits or broad OpenOrange host mount",
  severity: "high",
  probe: "D-NET-01",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { call, codeObj } of findWorkerLoaderCodeObjects(ctx)) {
      const props = propMap(codeObj);

      const limitsVal = props.get("limits");
      if (limitsVal?.type === "ObjectExpression") {
        const limitProps = propMap(limitsVal);
        const subReq = literalNumber(limitProps.get("subRequests"));
        if (subReq === 0) {
          findings.push(
            makeFinding(
              ctx.source,
              limitsVal,
              this,
              "Dynamic Worker specifies `limits: { subRequests: 0 }`. On Cloudflare production, " +
                "`subRequests: 0` is silently replaced by a 50-subrequest fallback rather than denying " +
                "outbound calls, and on both OSS workerd and OpenOrange `limits` is ignored completely.",
              "Do not rely on `limits.subRequests: 0` for zero-egress sandboxing. Pass `globalOutbound: null` " +
                "(or an allowlisting Fetcher) and omit network-capable bindings from the child `env`. " +
                "On OpenOrange, use `vmLimits` for heap/CPU bounds.",
            ),
          );
        }
      }

      const mountsVal = props.get("mounts");
      if (mountsVal?.type === "ArrayExpression") {
        const elements = (mountsVal["elements"] as (AstNode | null)[] | undefined) ?? [];
        for (const elem of elements) {
          if (!elem || elem.type !== "ObjectExpression") continue;
          const hostPath = literalString(propMap(elem).get("hostPath"))?.trim();
          if (!hostPath) continue;
          const isBroad =
            hostPath === "." ||
            hostPath === "./" ||
            hostPath === "/" ||
            hostPath.startsWith("..") ||
            SENSITIVE_MOUNT_RE.test(hostPath);
          if (!isBroad) continue;
          findings.push(
            makeFinding(
              ctx.source,
              elem,
              this,
              `OpenOrange Dynamic Worker mounts host path "${hostPath}" into the guest agentOS VM. ` +
                "Broad project-root or secret-bearing host mounts expose source code, `.dev.vars`, " +
                "`.open-orange/` local SQLite state, or credentials to untrusted dynamic Worker code.",
              "Mount only a dedicated, minimal build/asset subdirectory (never `.`, `/`, `..`, or " +
                "directories containing secrets or `.open-orange/` state).",
            ),
          );
        }
      }

      void call;
    }
    return findings;
  },
});

/**
 * WF-RIVET-05 — Dynamic Worker `LOADER.load()` / `LOADER.get()` invoked without
 * specifying `globalOutbound`. Completes the source-level counterpart to WF-EGR-02
 * across both Cloudflare Dynamic Workers and OpenOrange agentOS VMs.
 */
registerSource({
  id: "WF-RIVET-05",
  title: "Dynamic Worker loaded without explicit globalOutbound restriction",
  severity: "high",
  probe: "D-NET-01",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { call, codeObj } of findWorkerLoaderCodeObjects(ctx)) {
      const props = propMap(codeObj);
      if (props.has("globalOutbound")) continue;
      findings.push(
        makeFinding(
          ctx.source,
          call,
          this,
          "Worker Loader call omits `globalOutbound`. Both Cloudflare Dynamic Workers and OpenOrange " +
            "agentOS VMs default to unrestricted outbound network access when `globalOutbound` is omitted, " +
            "allowing untrusted child code to exfiltrate bindings or scan internal/cloud-metadata endpoints.",
          "Explicitly set `globalOutbound: null` (no network) or pass a dedicated allowlisting Fetcher " +
            "in the dynamic Worker code object.",
        ),
      );
    }
    return findings;
  },
});

/**
 * WF-RIVET-06 — RivetKit `actor({ actions: { ... } })` definition with no
 * `onAuth`, `onBeforeConnect`, or `createConnState` authentication hook.
 */
registerSource({
  id: "WF-RIVET-06",
  title: "RivetKit actor exposes actions without an authentication hook",
  severity: "high",
  probe: "D-DO-*",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      const path = calleeMemberPath(node);
      if (!path || path[path.length - 1] !== "actor") continue;
      const arg = callArgs(node)[0];
      if (!arg || arg.type !== "ObjectExpression") continue;
      const props = propMap(arg);
      const actions = props.get("actions");
      if (!actions || actions.type !== "ObjectExpression") continue;
      if (objectLiteralProperties(actions).length === 0) continue;
      const hasAuthHook = [...props.keys()].some((k) => ACTOR_AUTH_HOOKS.has(k));
      if (hasAuthHook) continue;
      findings.push(
        makeFinding(
          ctx.source,
          node,
          this,
          "RivetKit `actor()` defines callable `actions` without an `onAuth`, `onBeforeConnect`, or " +
            "`createConnState` hook. Any client able to reach the Rivet gateway with an actor connection " +
            "can invoke these actions without per-actor authorization.",
          "Add `onBeforeConnect` or `createConnState` (or `onAuth`) to verify the caller's token/identity " +
            "before accepting connections or executing actor actions.",
        ),
      );
    }
    return findings;
  },
});

function propMap(obj: AstNode): Map<string, AstNode> {
  const map = new Map<string, AstNode>();
  for (const prop of objectLiteralProperties(obj)) {
    const key = propKeyName(prop);
    const value = propValue(prop);
    if (key && value) map.set(key, value);
  }
  return map;
}

/**
 * Find `env.<LOADER>.load(codeObj)` and `env.<LOADER>.get(id, () => codeObj)` calls.
 * When `worker_loaders` bindings are declared in wrangler config we match those names;
 * otherwise we still match bindings named `*LOADER*` so source-only audits work.
 */
function findWorkerLoaderCodeObjects(
  ctx: Parameters<Parameters<typeof registerSource>[0]["check"]>[0],
): { call: AstNode; codeObj: AstNode }[] {
  const configuredLoaders = bindingNamesOfType(ctx.config, "worker_loader" as never);
  const rawLoaders = ((ctx.config["worker_loaders"] as { binding?: string; name?: string }[] | undefined) ?? [])
    .map((b) => b.binding ?? b.name)
    .filter((n): n is string => Boolean(n));
  const loaderNames = new Set([...configuredLoaders, ...rawLoaders]);

  const out: { call: AstNode; codeObj: AstNode }[] = [];
  for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
    const path = calleeMemberPath(node);
    if (!path || path.length < 2) continue;
    const method = path[path.length - 1];
    if (method !== "load" && method !== "get") continue;

    const callee = node["callee"] as AstNode | undefined;
    const receiver = callee?.["object"] as AstNode | undefined;
    if (!receiver) continue;

    const envHits = findEnvAccess(
      receiver,
      ctx.bindingMap.envNames,
      loaderNames.size > 0 ? loaderNames : undefined,
    );
    const isLoaderReceiver =
      loaderNames.size > 0
        ? envHits.length > 0
        : envHits.some((h) => /loader/i.test(h.binding));
    if (!isLoaderReceiver) continue;

    const args = callArgs(node);
    const candidate = method === "load" ? args[0] : extractReturnedObject(args[1]);
    if (!candidate || candidate.type !== "ObjectExpression") continue;
    // Confirm it looks like a WorkerCode object (has `modules` or `mainModule`).
    const keys = propMap(candidate);
    if (!keys.has("modules") && !keys.has("mainModule")) continue;
    out.push({ call: node, codeObj: candidate });
  }
  return out;
}

function extractReturnedObject(fn: AstNode | undefined): AstNode | undefined {
  if (!fn) return undefined;
  if (fn.type === "ObjectExpression") return fn;
  if (fn.type === "ArrowFunctionExpression" || fn.type === "FunctionExpression") {
    const body = fn["body"] as AstNode | undefined;
    if (!body) return undefined;
    if (body.type === "ObjectExpression") return body;
    if (body.type === "BlockStatement") {
      for (const { node } of findNodes(body, "ReturnStatement")) {
        const arg = node["argument"] as AstNode | undefined;
        if (arg?.type === "ObjectExpression") return arg;
      }
    }
  }
  return undefined;
}
