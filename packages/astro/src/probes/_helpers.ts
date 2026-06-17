import type { ProbeResult } from "@wulf/shared";
import type { Env } from "../index.js";

export function now(): string {
  return new Date().toISOString();
}

export function base(partial: Omit<ProbeResult, "timestamp">): ProbeResult {
  return { timestamp: now(), ...partial };
}

/** Resolve the Astro target base URL (service binding preferred, else URL var). */
export function targetBase(env: Env): string {
  return (env.ASTRO_TARGET_URL as string) ?? "http://127.0.0.1:8788";
}

/** Fetch a path on the Astro app under test, via service binding if bound, else plain fetch. */
export function targetFetch(env: Env, path: string, init?: RequestInit): Promise<Response> {
  const url = new URL(path, targetBase(env)).toString();
  if (env.ASTRO && typeof env.ASTRO.fetch === "function") {
    return env.ASTRO.fetch(new Request(url, init)) as unknown as Promise<Response>;
  }
  return fetch(url, init);
}

export interface IslandBlobs {
  componentId: string;
  e: string; // encryptedComponentExport
  p: string; // encryptedProps
  s: string; // encryptedSlots
  via: "get-url" | "post-data";
}

/**
 * Fetch a page that renders a `server:defer` island and extract its encrypted
 * blobs (componentExport `e`, props `p`, slots `s`). Handles both the GET-URL
 * form (`_server-islands/<id>?s=&e=&p=`) and the inline POST-data object form.
 * Returns `undefined` if no island markers are found on the page.
 */
export async function harvestIslandBlobs(env: Env, pagePath: string): Promise<IslandBlobs | undefined> {
  const res = await targetFetch(env, pagePath);
  const html = await res.text();

  const idMatch = html.match(/_server-islands\/([^/?"'\s]+)/);
  if (!idMatch) return undefined;
  const componentId = decodeURIComponent(idMatch[1]!);

  // GET-URL form: ?s=...&e=...&p=...
  const get = (k: string) => {
    // `*` (not `+`): the slots param `s=` is empty when an island has no slots.
    const m = html.match(new RegExp(`[?&]${k}=([^&"'\\\\\\s]*)`));
    return m ? decodeURIComponent(m[1]!) : undefined;
  };
  let e = get("e");
  let p = get("p");
  let s = get("s");
  if (e !== undefined && p !== undefined && s !== undefined) {
    return { componentId, e, p, s, via: "get-url" };
  }

  // POST-data form: encryptedComponentExport:"...", encryptedProps:"...", encryptedSlots:"..."
  const field = (name: string) => {
    const m = html.match(new RegExp(`${name}\\s*:\\s*"([^"]*)"`));
    return m ? m[1]! : undefined;
  };
  e = field("encryptedComponentExport");
  p = field("encryptedProps");
  s = field("encryptedSlots");
  if (e !== undefined && p !== undefined && s !== undefined) {
    return { componentId, e, p, s, via: "post-data" };
  }
  return undefined;
}

/** Origin of the Astro target (for same-origin requests that pass checkOrigin). */
export function targetOrigin(env: Env): string {
  return new URL(targetBase(env)).origin;
}

export interface ActionPostOpts {
  body?: BodyInit | null;
  contentType?: string;
  /** Set Origin to the target's own origin so the request passes checkOrigin (default true). */
  sameOrigin?: boolean;
  /** Override the Origin header explicitly (for CSRF tests). */
  origin?: string;
}

/** POST to an action endpoint `/_actions/<name>` with controllable headers/body. */
export function actionPost(env: Env, name: string, opts: ActionPostOpts = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (opts.contentType) headers["content-type"] = opts.contentType;
  if (opts.origin !== undefined) headers["origin"] = opts.origin;
  else if (opts.sameOrigin !== false) headers["origin"] = targetOrigin(env);
  return targetFetch(env, `/_actions/${name}`, {
    method: "POST",
    headers,
    body: opts.body ?? null,
  });
}

/** Build a multipart/form-data body + content-type from a field map. */
export function multipartBody(
  fields: Record<string, string>,
  boundary = "----wulf",
): { body: string; contentType: string } {
  let body = "";
  for (const [k, v] of Object.entries(fields)) {
    body += `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`;
  }
  body += `--${boundary}--\r\n`;
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}

/** Build a urlencoded body + content-type from a field map. */
export function urlencodedBody(fields: Record<string, string>): { body: string; contentType: string } {
  return {
    body: new URLSearchParams(fields).toString(),
    contentType: "application/x-www-form-urlencoded",
  };
}

/** Build a POST to the server-island endpoint with the given encrypted blobs. */
export function islandPost(env: Env, componentId: string, body: unknown): Promise<Response> {
  return targetFetch(env, `/_server-islands/${encodeURIComponent(componentId)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}
