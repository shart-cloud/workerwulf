import type { WsResult } from "../../dast/http.js";
import { registerProbe, type Finding } from "../../engine/rule.js";
import { excerpt, probeFinding, sameOriginUrl } from "./_utils.js";

/**
 * WebSocket endpoints that front Durable Objects. Agents SDK routes are
 * /agents/<kebab-class>/<instance>; PartyServer routes are
 * /parties/<party>/<room>. Connecting creates (or wakes) the named instance —
 * the instance name is a nonce so no real user's object is touched.
 */
function candidatePaths(nonce: string, extra: string[]): { path: string; kind: "agents" | "partyserver" | "generic" }[] {
  const out: { path: string; kind: "agents" | "partyserver" | "generic" }[] = [];
  for (const cls of ["chat", "agent", "my-agent", "chat-agent", "mcp"]) {
    out.push({ path: `/agents/${cls}/wulf-${nonce}`, kind: "agents" });
  }
  for (const party of ["main", "chat", "game"]) {
    out.push({ path: `/parties/${party}/wulf-${nonce}`, kind: "partyserver" });
  }
  for (const p of ["/ws", "/websocket", "/socket", "/connect", ...extra]) {
    out.push({ path: p, kind: "generic" });
  }
  return out;
}

/** Agents SDK pushes these to every new connection before any auth hook runs. */
function agentStateLeak(res: WsResult): string | undefined {
  for (const m of res.messages) {
    try {
      const msg = JSON.parse(m) as { type?: string; state?: unknown };
      if (msg.type === "cf_agent_state" && msg.state !== undefined && msg.state !== null) {
        const s = JSON.stringify(msg.state);
        if (s !== "{}" && s !== "[]") return s;
      }
    } catch {
      // non-JSON frame
    }
  }
  return undefined;
}

registerProbe({
  id: "WF-DAST-WS-01",
  title: "Durable Object WebSocket accepts unauthenticated upgrade",
  severity: "medium",
  probe: "AI-INJ-*",
  family: "DAST",
  async check(ctx) {
    const findings: Finding[] = [];
    const extra = ctx.paths.filter((p) => p !== "/");
    for (const { path, kind } of candidatePaths(ctx.nonce(), extra)) {
      const url = sameOriginUrl(ctx, path);
      const res = await ctx.http.websocket({ url, headers: { origin: `https://wulf-${ctx.nonce()}.invalid` } });
      if (!res.accepted) continue;
      const state = kind === "agents" ? agentStateLeak(res) : undefined;
      const what =
        kind === "agents" ? "Cloudflare Agents SDK agent" : kind === "partyserver" ? "PartyServer room" : "WebSocket endpoint";
      findings.push(
        probeFinding(
          this,
          url,
          `${what} at ${path} completed a WebSocket upgrade with no credentials and a foreign Origin.` +
            (state
              ? " On connect it broadcast the agent's persisted state (cf_agent_state) to the anonymous client."
              : " Any site can open this socket from a victim's browser (no Origin check), and anyone can address arbitrary instance names."),
          kind === "agents"
            ? "Authenticate in routeAgentRequest's onBeforeConnect hook (or in the Worker before routing), check the Origin header, and keep secrets out of setState() — state is pushed to every connection."
            : "Authenticate and check Origin in the Worker before forwarding the upgrade to the Durable Object; derive the object name from the authenticated principal rather than the URL.",
          [
            {
              type: "http",
              label: `WS ${path}`,
              inline: [
                "< 101 Switching Protocols",
                ...res.messages.slice(0, 4).map((m) => `< frame: ${excerpt(m, 300)}`),
              ].join("\n"),
            },
          ],
          state ? "high" : "medium",
        ),
      );
    }
    return findings;
  },
});
