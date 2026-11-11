import { registerProbe, type Finding } from "../../engine/rule.js";
import { httpEvidence, probeFinding, sameOriginUrl } from "./_utils.js";

registerProbe({
  id: "WF-DAST-CORS-01",
  title: "CORS reflects arbitrary Origin",
  severity: "high",
  probe: "WF-REQ-CORS-01",
  family: "DAST",
  async check(ctx) {
    const findings: Finding[] = [];
    for (const path of ctx.paths) {
      const url = sameOriginUrl(ctx, path);
      for (const origin of [`https://wulf-${ctx.nonce()}.invalid`, "null"]) {
        const headers = { origin };
        const res = await ctx.http.request({ url, headers });
        const acao = res.headers["access-control-allow-origin"];
        const creds = /^true$/i.test(res.headers["access-control-allow-credentials"] ?? "");
        if (acao === origin) {
          findings.push(
            probeFinding(
              this,
              url,
              `${path} echoes an attacker-chosen Origin (${origin}) into Access-Control-Allow-Origin${creds ? " with Access-Control-Allow-Credentials: true — any site can read this route's responses using the victim's cookies" : ""}.`,
              "Match Origin against an explicit allowlist before setting Access-Control-Allow-Origin, add `Vary: Origin`, and never pair a reflected or `null` origin with credentials.",
              [httpEvidence(`${path} with Origin: ${origin}`, res, { requestHeaders: headers })],
              creds ? "high" : "medium",
            ),
          );
          break;
        }
        if (acao === "*" && origin !== "null") {
          findings.push(
            probeFinding(
              this,
              url,
              `${path} sends Access-Control-Allow-Origin: * — any origin can read unauthenticated responses from this route.`,
              "Use an allowlist if the route returns anything binding-backed (KV, D1, R2, AI). Wildcard is only appropriate for genuinely public data.",
              [httpEvidence(`${path} with Origin: ${origin}`, res, { requestHeaders: headers })],
              "informational",
            ),
          );
          break;
        }
      }
    }
    return findings;
  },
});
