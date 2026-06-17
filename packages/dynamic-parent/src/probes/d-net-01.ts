import type { Probe } from "./index.js";
import { buildCallbackHttpTarget } from "@wulf/shared";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dNet01: Probe = async ({ env, req, runId }) => {
  const url = new URL(req.url);
  const target =
    url.searchParams.get("target") ??
    (env.WULF_CALLBACK_HTTP_BASE
      ? buildCallbackHttpTarget({
          base: env.WULF_CALLBACK_HTTP_BASE,
          testId: "D-NET-01",
          runId,
          track: "dynamic",
        })
      : "https://cloudflare.com/cdn-cgi/trace");

  // First: child WITHOUT globalOutbound restriction — should reach target.
  const openStub = loadChild(env);
  const openResp = await invokeChild(openStub, "try-fetch", { target });

  // Then: child WITH globalOutbound: null — should fail.
  const closedStub = loadChild(env, { globalOutbound: null });
  const closedResp = await invokeChild(closedStub, "try-fetch", { target });

  type FetchData = { reachable: boolean; status?: number; error?: string };
  const open = (openResp.body as { data: FetchData }).data;
  const closed = (closedResp.body as { data: FetchData }).data;

  const blockedCorrectly = open.reachable === true && closed.reachable === false;

  return base({
    test_id: "D-NET-01",
    track: "dynamic",
    description: "globalOutbound:null blocks child fetch(); open child still reaches",
    target,
    result: blockedCorrectly ? "blocked" : "accessible",
    severity: blockedCorrectly ? "informational" : "high",
    run_id: runId,
    details: {
      open_child: open,
      closed_child: closed,
      enforcement_correct: blockedCorrectly,
    },
  });
};
