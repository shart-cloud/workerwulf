import type { Probe } from "./index.js";
import { buildCallbackHttpTarget } from "@wulf/shared";
import { base } from "./_helpers.js";

async function dynamicImport<T>(url: string): Promise<T> {
  return import(url);
}

export const wDyn03: Probe = async ({ env, runId }) => {
  const details: Record<string, unknown> = {};

  // Test 1: data: URI import
  try {
    const mod = await dynamicImport("data:text/javascript,export default 'hello from data uri'");
    details.data_uri_import = {
      success: true,
      result: (mod as { default?: unknown }).default,
    };
  } catch (err) {
    details.data_uri_import = {
      success: false,
      error: err instanceof Error ? err.message : String(err),
      error_name: err instanceof Error ? err.name : null,
    };
  }

  // Test 2: remote URL import (against callback server if available)
  if (env.WULF_CALLBACK_HTTP_BASE) {
    const target = buildCallbackHttpTarget({
      base: env.WULF_CALLBACK_HTTP_BASE,
      testId: "W-DYN-03",
      runId,
      track: "worker",
      extra: { type: "import" },
    });
    try {
      await dynamicImport(target);
      details.remote_url_import = { success: true, url: target };
    } catch (err) {
      details.remote_url_import = {
        success: false,
        error: err instanceof Error ? err.message : String(err),
        error_name: err instanceof Error ? err.name : null,
      };
    }
  } else {
    // Fallback: try known remote URL
    try {
      await dynamicImport("https://cloudflare.com/cdn-cgi/trace");
      details.remote_url_import = { success: true };
    } catch (err) {
      details.remote_url_import = {
        success: false,
        error: err instanceof Error ? err.message : String(err),
        error_name: err instanceof Error ? err.name : null,
      };
    }
  }

  // Test 3: relative import (non-existent module to see error behavior)
  try {
    await dynamicImport("./wulf-nonexistent-module.js");
    details.relative_import = { success: true };
  } catch (err) {
    details.relative_import = {
      success: false,
      error: err instanceof Error ? err.message : String(err),
      error_name: err instanceof Error ? err.name : null,
    };
  }

  // Test 4: import with full URL (not just path)
  try {
    await dynamicImport("https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js");
    details.cdn_import = { success: true };
  } catch (err) {
    details.cdn_import = {
      success: false,
      error: err instanceof Error ? err.message : String(err),
      error_name: err instanceof Error ? err.name : null,
    };
  }

  const anySuccessful = [details.data_uri_import, details.remote_url_import, details.relative_import, details.cdn_import]
    .some((r) => r && typeof r === "object" && (r as Record<string, unknown>).success === true);

  return base({
    test_id: "W-DYN-03",
    track: "worker",
    description: "Test dynamic import() at runtime — data: URIs, remote URLs, relative paths",
    result: "informational",
    severity: anySuccessful ? "medium" : "informational",
    run_id: runId,
    details,
    comparison: {
      aws_lambda: "blocked (import requires bundler)",
      azure_functions: "blocked (import requires bundler)",
      gcp_functions: "blocked (import requires bundler)",
    },
  });
};
