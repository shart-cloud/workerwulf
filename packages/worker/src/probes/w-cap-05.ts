import puppeteer from "@cloudflare/puppeteer";
import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-CAP-05 — Browser Rendering capability-binding blast radius (SSRF-with-a-browser).
 *
 * A Worker bound to Browser Rendering can launch a headless Chromium and drive it
 * to fetch and render arbitrary URLs — a far stronger SSRF/exfil primitive than a
 * bare `fetch()`: it executes JS, follows redirects, and can screenshot or scrape
 * any reachable origin (including internal/metadata endpoints) from Cloudflare's
 * egress. This probe drives the browser to a target URL and reports what it could
 * retrieve.
 *
 * Deploy-only: requires the live BROWSER binding. Locally → blocked.
 */
export const wCap05: Probe = async ({ env, req, runId }) => {
  const browserBinding = env.BROWSER;
  if (!browserBinding) {
    return base({
      test_id: "W-CAP-05",
      track: "worker",
      description:
        "Browser Rendering capability binding — drive a headless browser to fetch/render arbitrary URLs (SSRF-with-a-browser)",
      target: "env.BROWSER",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: { error: "BROWSER binding not present (expected locally / pre-deploy)" },
    });
  }

  const url = new URL(req.url);
  const target = url.searchParams.get("target") ?? "https://example.com/";

  let status: number | null = null;
  let title: string | null = null;
  let contentPreview: string | null = null;
  let finalUrl: string | null = null;
  let error: string | null = null;
  let rendered = false;

  try {
    const browser = await puppeteer.launch(browserBinding);
    try {
      const page = await browser.newPage();
      const resp = await page.goto(target, { waitUntil: "domcontentloaded" });
      status = resp?.status() ?? null;
      finalUrl = page.url();
      title = await page.title();
      contentPreview = (await page.content()).slice(0, 1024);
      rendered = true;
    } finally {
      await browser.close();
    }
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return base({
    test_id: "W-CAP-05",
    track: "worker",
    description:
      "Browser Rendering capability binding — drive a headless browser to fetch/render arbitrary URLs (SSRF-with-a-browser)",
    target: "env.BROWSER",
    result: rendered ? "accessible" : error ? "error" : "partial",
    severity: rendered ? "high" : "medium",
    run_id: runId,
    tags: ["misconfig", "misconfig:binding"],
    details: {
      requested_target: target,
      final_url: finalUrl,
      http_status: status,
      page_title: title,
      content_preview: contentPreview,
      error,
      note: "A Browser Rendering binding is a full headless browser at the Worker's disposal — arbitrary URL fetch + JS execution + screenshot from Cloudflare egress. Pass ?target=<url> to point it at an internal/metadata endpoint to demonstrate SSRF reach.",
    },
    comparison: {
      aws_lambda: "n/a — would require bundling a headless browser; not a default capability",
      azure_functions: "n/a",
      gcp_functions: "n/a",
    },
  });
};
