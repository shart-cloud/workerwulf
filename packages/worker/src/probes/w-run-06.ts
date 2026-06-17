import type { Probe } from "./index.js";
import { buildCallbackHttpTarget } from "@wulf/shared";
import { base } from "./_helpers.js";

let originalFetch: typeof fetch | null = null;
let hookInstalled = false;
let hookFiredCount = 0;

export const wRun06: Probe = async ({ env, req, runId }) => {
  const seqValue = new URL(req.url).searchParams.get("seq");
  const seq = seqValue ? parseInt(seqValue, 10) : 0;
  const details: Record<string, unknown> = { seq };

  const target =
    env.WULF_CALLBACK_HTTP_BASE
      ? buildCallbackHttpTarget({
          base: env.WULF_CALLBACK_HTTP_BASE,
          testId: "W-RUN-06",
          runId,
          track: "worker",
          extra: { seq: String(seq) },
        })
      : "https://cloudflare.com/cdn-cgi/trace";

  if (seq === 0) {
    // HOOK phase
    if (!originalFetch) {
      originalFetch = fetch;
      const g = globalThis as unknown as Record<string, typeof fetch>;
      g.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
        hookFiredCount++;
        const hookedInit = { ...init };
        const h = new Headers(init?.headers);
        h.set("X-Wulf-Hook", "intercepted");
        if (typeof input === "string") {
          (hookedInit as Record<string, unknown>).headers = h;
        } else if (input instanceof Request) {
          for (const [k, v] of h) {
            (input as Request).headers.set(k, v);
          }
          (hookedInit as Record<string, unknown>).headers = (input as Request).headers;
        } else {
          (hookedInit as Record<string, unknown>).headers = h;
        }
        return originalFetch!(input, hookedInit);
      }) as typeof fetch;
      hookInstalled = true;
    }

    details.phase = "hook";
    details.hook_installed = hookInstalled;
    details.header_name = "X-Wulf-Hook";
    details.header_value = "intercepted";
    details.original_saved = originalFetch !== null;
  } else if (seq === 1) {
    // TEST phase — make outbound request and see if hook fires
    details.phase = "test";
    const g = globalThis as unknown as Record<string, typeof fetch>;
    const fetchFn = g.fetch ?? fetch;

    try {
      const res = await fetchFn(target, {
        method: "GET",
        headers: { "user-agent": "wulf-hook-test" },
        signal: AbortSignal.timeout(5000),
      });
      const text = await res.text();
      details.http_status = res.status;
      details.response_preview = text.slice(0, 256);
      details.hook_did_fire = hookFiredCount > 0;
      details.hook_fired_count = hookFiredCount;
    } catch (err) {
      details.fetch_error = err instanceof Error ? err.message : String(err);
      details.hook_did_fire = hookFiredCount > 0;
    }
  } else {
    // RESTORE phase (seq=2+)
    details.phase = "restore";
    if (originalFetch) {
      const g = globalThis as unknown as Record<string, typeof fetch>;
      g.fetch = originalFetch;
      details.original_restored = true;
    } else {
      details.original_restored = false;
      details.note = "No original fetch reference to restore";
    }
  }

  return base({
    test_id: "W-RUN-06",
    track: "worker",
    description:
      "Monkey-patch fetch() on request A, verify hook fires on request B, restore on request C",
    result: seq === 1 && details.hook_did_fire === true ? "accessible" : "blocked",
    severity: seq === 1 && details.hook_did_fire === true ? "high" : "informational",
    run_id: runId,
    details: {
      ...details,
      injected_header_present: details.hook_did_fire === true,
      header_name: "X-Wulf-Hook",
      header_value: "intercepted",
      hook_fired_count: hookFiredCount,
      note:
        seq === 0
          ? "Monkey-patched fetch() — hook installed"
          : seq === 1 && details.hook_did_fire === true
            ? "Hook FIRED on subsequent request — monkey-patched fetch() persists and intercepts all outbound traffic"
            : seq === 1
              ? "Hook did NOT fire — persistence model is one-request-only"
              : "Original fetch() restored",
    },
    comparison: {
      aws_lambda: "accessible (monkey-patching persists in warm container)",
      azure_functions: "accessible (monkey-patching persists in warm instance)",
      gcp_functions: "accessible (monkey-patching persists in warm instance)",
    },
  });
};
