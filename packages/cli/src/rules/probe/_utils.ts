import { pathOf, type Fingerprint } from "../../dast/fingerprint.js";
import type { ProbeResponse } from "../../dast/http.js";
import type { Evidence, Finding, ProbeRule, Severity } from "../../engine/rule.js";

type RuleMeta = Pick<ProbeRule, "id" | "title" | "severity" | "probe" | "family">;

export function probeFinding(
  rule: RuleMeta,
  url: string,
  message: string,
  remediation: string,
  evidence: Evidence[],
  severity: Severity = rule.severity,
): Finding {
  return {
    rule_id: rule.id,
    title: rule.title,
    severity,
    resource: `url:${pathOf(url)}`,
    message,
    remediation,
    probe: rule.probe,
    family: rule.family,
    evidence,
  };
}

const EVIDENCE_HEADERS = [
  "content-type",
  "cache-control",
  "cf-cache-status",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "location",
  "server",
  "cf-ray",
];

/** Compact request/response evidence: status, selected headers, body excerpt. */
export function httpEvidence(
  label: string,
  res: ProbeResponse,
  opts: { method?: string; body?: string; requestHeaders?: Record<string, string> } = {},
): Evidence {
  const lines = [`${opts.method ?? "GET"} ${pathOf(res.url)}`];
  for (const [k, v] of Object.entries(opts.requestHeaders ?? {})) lines.push(`> ${k}: ${v}`);
  lines.push(`< ${res.status}`);
  for (const h of EVIDENCE_HEADERS) {
    const v = res.headers[h];
    if (v !== undefined) lines.push(`< ${h}: ${v}`);
  }
  const body = opts.body ?? res.body;
  if (body) lines.push("", excerpt(body, 400));
  return { type: "http", label, inline: lines.join("\n") };
}

export function excerpt(text: string, max: number): string {
  const flat = text.replace(/\r/g, "");
  return flat.length > max ? `${flat.slice(0, max)}…[${flat.length - max} more bytes]` : flat;
}

/**
 * True when `res` is indistinguishable from the target's response to a
 * certainly-missing path — SPAs and catch-all Workers answer every path with
 * 200 + index.html, which must not read as "file exposed".
 */
export function isSoft404(res: ProbeResponse, fp: Fingerprint): boolean {
  if (res.status === 404 || res.status === 410) return true;
  if (res.status !== fp.not_found.status) return false;
  return normalize(res.body) === normalize(fp.not_found.body);
}

function normalize(body: string): string {
  // Strip per-request noise (nonces, ray IDs, timestamps) before comparing.
  return body
    .replace(/wulf-[0-9a-f]{8,}/gi, "")
    .replace(/[0-9a-f]{16}(-[A-Z]{3})?/g, "")
    .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?/g, "")
    .trim();
}

export function isHtml(res: ProbeResponse): boolean {
  return /text\/html/i.test(res.headers["content-type"] ?? "") || /^\s*<(!doctype|html)/i.test(res.body);
}

/** Replace every `KEY=value` value with a length marker — never echo secrets. */
export function redactEnv(text: string): string {
  return text.replace(/^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(.*)$/gm, (_m, key: string, value: string) => {
    const v = value.trim().replace(/^["']|["']$/g, "");
    return `${key}<redacted ${v.length} chars>`;
  });
}

export function sameOriginUrl(ctx: { target: URL }, path: string): string {
  return new URL(path, ctx.target.origin).toString();
}
