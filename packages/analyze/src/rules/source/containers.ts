import { isMemberAccess, objectLiteralProperties } from "../../ast/nodes.js";
import type { AstNode } from "../../ast/parse.js";
import { calleeMemberPath, isStringConcat, templateHasExpressions } from "../../ast/patterns.js";
import { findNodes } from "../../ast/walk.js";
import { registerSource, type Finding } from "../../engine/rule.js";
import {
  buildRequestTaint,
  callArgs,
  isRequestDerived,
  literalString,
  makeFinding,
  propKeyName,
  propValue,
} from "./_utils.js";

const SHELL_BIN_RE = /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|dash|zsh|ash)$/i;

function isContainerCall(node: AstNode, method: string): boolean {
  const path = calleeMemberPath(node);
  if (!path || path.length < 2 || path[path.length - 1] !== method) return false;
  const receiver = path.slice(0, -1).join(".").toLowerCase();
  return receiver === "container" || receiver.endsWith(".container");
}

function propMap(obj: AstNode): Map<string, AstNode> {
  const map = new Map<string, AstNode>();
  for (const prop of objectLiteralProperties(obj)) {
    const key = propKeyName(prop);
    const val = propValue(prop);
    if (key && val) map.set(key, val);
  }
  return map;
}

/**
 * WF-CTR-02 — Wave 6 (W-CTR-02). `ctx.container.exec(["sh", "-c", ...])` with a
 * dynamically constructed command string. W-CTR-02 proved that direct argv is
 * literal while a shell hop yields arbitrary uid-0 command execution.
 */
registerSource({
  id: "WF-CTR-02",
  title: "Container exec() invokes a shell with a dynamic command string",
  severity: "critical",
  probe: "W-CTR-02",
  family: "B",
  check(ctx) {
    const tainted = buildRequestTaint(ctx.source);
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isContainerCall(node, "exec")) continue;
      const argv = callArgs(node)[0];
      if (!argv || argv.type !== "ArrayExpression") continue;
      const elems = (argv["elements"] as (AstNode | null)[] | undefined) ?? [];
      const bin = literalString(elems[0] ?? undefined);
      const flag = literalString(elems[1] ?? undefined);
      const cmd = elems[2] ?? undefined;
      if (!bin || !SHELL_BIN_RE.test(bin) || flag !== "-c" || !cmd) continue;
      const isDynamic =
        cmd.type !== "Literal" &&
        (isRequestDerived(cmd, tainted) ||
          isStringConcat(cmd) ||
          templateHasExpressions(cmd) ||
          cmd.type === "Identifier" ||
          cmd.type === "CallExpression" ||
          isMemberAccess(cmd));
      if (!isDynamic) continue;
      findings.push(
        makeFinding(
          ctx.source,
          node,
          this,
          `\`container.exec()\` invokes \`${bin} -c\` with a non-literal command string. W-CTR-02 ` +
            "demonstrated that shell interpolation inside a Cloudflare Container grants full uid-0 " +
            "command execution, `/proc/1/environ` secret harvest (W-CTR-04), raw TCP egress (W-CTR-05), " +
            "and persistent background processes (W-CTR-06).",
          "Avoid shell wrappers (`sh -c`). Pass the target binary and fixed argv array directly to " +
            "`ctx.container.exec([binary, ...args])` so untrusted values stay literal arguments.",
        ),
      );
    }
    return findings;
  },
});

/**
 * WF-CTR-03 — Wave 6 (W-CTR-07). Passing a non-numeric `user` string (such as
 * `"nobody"`) to `ctx.container.exec(argv, { user })`. W-CTR-07 proved non-numeric
 * usernames are not honored (only numeric uid strings resolve), leaving a false
 * sense of privilege reduction while the container defaults to uid 0.
 */
registerSource({
  id: "WF-CTR-03",
  title: "Container exec() passes a non-numeric `user` name that is not honored",
  severity: "high",
  probe: "W-CTR-07",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isContainerCall(node, "exec")) continue;
      const opts = callArgs(node)[1];
      if (!opts || opts.type !== "ObjectExpression") continue;
      const userVal = propMap(opts).get("user");
      const userStr = literalString(userVal);
      if (!userStr) continue;
      if (/^\d+(?::\d+)?$/.test(userStr.trim())) continue;
      findings.push(
        makeFinding(
          ctx.source,
          userVal!,
          this,
          `\`container.exec()\` sets \`user: "${userStr}"\`. W-CTR-07 deploy-verified that named users ` +
            'like `"nobody"` are not honored by Cloudflare Containers `exec()` — only numeric uids resolve. ' +
            "Relying on a named `user` option creates a false privilege-reduction control.",
          'Specify a numeric uid (e.g. `"65534"` or `"1000"`) and verify `id -u` at runtime, or drop ' +
            "privileges inside the container image (`USER 65534` in the Dockerfile).",
        ),
      );
    }
    return findings;
  },
});

/**
 * WF-CTR-04 — Wave 6 (W-CTR-05). `ctx.container.start(...)` called without
 * `enableInternet: false`. W-CTR-05 proved that `enableInternet: false` is an
 * effective egress boundary for exec'd processes, whereas default/enabled egress
 * allows raw TCP on arbitrary ports (e.g. port 22) that isolate `fetch()` blocks.
 */
registerSource({
  id: "WF-CTR-04",
  title: "Container started without enableInternet: false",
  severity: "medium",
  probe: "W-CTR-05",
  family: "E",
  check(ctx) {
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (!isContainerCall(node, "start")) continue;
      const opts = callArgs(node)[0];
      if (opts?.type === "ObjectExpression") {
        const enableInternet = propMap(opts).get("enableInternet");
        if (enableInternet?.type === "Literal" && enableInternet["value"] === false) {
          continue;
        }
      }
      findings.push(
        makeFinding(
          ctx.source,
          node,
          this,
          "`container.start()` does not set `enableInternet: false`. W-CTR-05 demonstrated that " +
            "container processes inherit a full POSIX socket layer (raw TCP to port 22, arbitrary ports, " +
            "and direct DNS) that bypasses isolate `fetch()` restrictions.",
          "Pass `{ enableInternet: false }` to `ctx.container.start()` for untrusted workloads, or " +
            "install `interceptAllOutboundHttp()` / `interceptOutboundHttp()` to mediate container egress.",
        ),
      );
    }
    return findings;
  },
});

/**
 * WF-CTR-05 — Wave 6 (W-CTR-04 / W-CTR-11).
 *  (a) Request-derived `env` passed into `container.exec()` (caller can set
 *      `LD_PRELOAD` or hijack `PATH`, verified in W-CTR-04).
 *  (b) Request-derived port passed into `container.getTcpPort()` (W-CTR-11 proved
 *      `getTcpPort()` reaches undeclared ports opened by `exec()`).
 */
registerSource({
  id: "WF-CTR-05",
  title: "Request-derived env or TCP port passed to Container exec() / getTcpPort()",
  severity: "high",
  probe: "W-CTR-04",
  family: "B",
  check(ctx) {
    const tainted = buildRequestTaint(ctx.source);
    const findings: Finding[] = [];
    for (const { node } of findNodes(ctx.source.ast, "CallExpression")) {
      if (isContainerCall(node, "exec")) {
        const opts = callArgs(node)[1];
        if (!opts || opts.type !== "ObjectExpression") continue;
        const envVal = propMap(opts).get("env");
        if (envVal && isRequestDerived(envVal, tainted)) {
          findings.push(
            makeFinding(
              ctx.source,
              envVal,
              this,
              "Request-derived values flow into `container.exec()` `env`. W-CTR-04 confirmed that " +
                "caller-controlled `env` overrides `PATH` and `LD_PRELOAD`, turning even fixed-argv " +
                "executions into arbitrary code execution inside the container.",
              "Construct `env` from a strict allowlist of non-loader keys (never permit `LD_PRELOAD`, " +
                "`LD_LIBRARY_PATH`, `PATH`, `NODE_OPTIONS`, or `PYTHONPATH` from caller input).",
            ),
          );
        }
      } else if (isContainerCall(node, "getTcpPort")) {
        const portArg = callArgs(node)[0];
        if (portArg && isRequestDerived(portArg, tainted)) {
          findings.push(
            makeFinding(
              ctx.source,
              node,
              this,
              "`container.getTcpPort()` is called with a request-derived port. W-CTR-11 proved that " +
                "`getTcpPort()` connects to any listening port inside the container — including undeclared " +
                "internal services or ports opened dynamically by `exec()`.",
              "Pass a hardcoded constant or validate the port against an explicit allowlist of declared service ports.",
            ),
          );
        }
      }
    }
    return findings;
  },
});
