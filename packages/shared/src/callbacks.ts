import type { Track } from "./index.js";

function sanitizeLabel(input: string, max = 40): string {
  const label = input
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max);
  return label || "x";
}

function trimDot(name: string): string {
  return name.replace(/\.+$/, "");
}

function nonce(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function joinBase(base: string, path: string): string {
  return `${base.replace(/\/+$/, "")}${path}`;
}

function encodeQuery(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
}

export function buildCallbackHttpTarget(args: {
  base: string;
  testId: string;
  runId: string;
  track: Track;
  nonce?: string;
  extra?: Record<string, string>;
}): string {
  const params = encodeQuery({
    track: args.track,
    test_id: args.testId,
    run_id: args.runId,
    nonce: args.nonce ?? nonce(),
    ...(args.extra ?? {}),
  });
  return `${joinBase(args.base, "/callback")}?${params}`;
}

export function buildControlledHostname(args: {
  zone: string;
  testId: string;
  runId: string;
  nonce?: string;
  prefix?: string;
}): string {
  const labels = [
    args.prefix ? sanitizeLabel(args.prefix, 16) : null,
    sanitizeLabel(args.testId, 20),
    sanitizeLabel(args.runId, 24),
    sanitizeLabel(args.nonce ?? nonce(), 20),
  ].filter(Boolean);
  return `${labels.join(".")}.${trimDot(args.zone)}`;
}

export function forceHttps(target: string): string {
  return target.replace(/^http:/, "https:");
}
