import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wNet04: Probe = async ({ req, runId }) => {
  const url = new URL(req.url);
  const target =
    url.searchParams.get("target") ?? "https://echo.websocket.org/";

  const tryUpgrade = async (): Promise<Record<string, unknown>> => {
    try {
      const res = await fetch(target, {
        headers: { Upgrade: "websocket" },
        signal: AbortSignal.timeout(3000),
      });
      return {
        method: "fetch_upgrade",
        status: res.status,
        webSocket_present: (res as unknown as { webSocket?: unknown }).webSocket != null,
        headers: Object.fromEntries(res.headers),
      };
    } catch (err) {
      return {
        method: "fetch_upgrade",
        error: err instanceof Error ? err.message : String(err),
      };
    }
  };

  const tryConstructor = (): Record<string, unknown> => {
    const Ctor = (globalThis as { WebSocket?: unknown }).WebSocket;
    if (typeof Ctor !== "function") {
      return { method: "new_WebSocket", available: false };
    }
    try {
      const wsCtor = Ctor as unknown as new (url: string) => unknown;
      const ws = new wsCtor(target);
      return {
        method: "new_WebSocket",
        available: true,
        constructed: ws != null,
      };
    } catch (err) {
      return {
        method: "new_WebSocket",
        available: true,
        constructed: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  };

  const upgradeResult = await tryUpgrade();
  const ctorResult = tryConstructor();
  const upgradeOk = upgradeResult["status"] === 101;

  return base({
    test_id: "W-NET-04",
    track: "worker",
    description: "WebSocket outbound connection attempts",
    target,
    result: upgradeOk ? "accessible" : "blocked",
    severity: "informational",
    run_id: runId,
    details: {
      fetch_upgrade: upgradeResult,
      new_websocket: ctorResult,
    },
  });
};
