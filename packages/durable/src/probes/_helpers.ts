import type { ProbeResult } from "@wulf/shared";

export function now(): string {
  return new Date().toISOString();
}

export function base(
  partial: Omit<ProbeResult, "timestamp">,
): ProbeResult {
  return { timestamp: now(), ...partial };
}

/**
 * Get or create a Durable Object stub for the given binding and test id.
 * Uses the test id as the DO name so each test gets a deterministic instance.
 */
export function getDoStub(
  env: { PREY_DO: DurableObjectNamespace; PREY_DO_SECURE: DurableObjectNamespace },
  binding: "PREY_DO" | "PREY_DO_SECURE",
  testId: string,
): DurableObjectStub {
  const ns = env[binding];
  const id = ns.idFromName(testId);
  return ns.get(id);
}

export interface DoEnvelope<T> {
  ok?: boolean;
  data?: T;
  error?: string;
  stack?: string | null;
}

export async function doFetch<T>(
  stub: DurableObjectStub,
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<T> {
  const res = await stub.fetch(input, init);
  const body = (await res.json()) as DoEnvelope<T>;
  if (!res.ok || body.ok === false) {
    throw new Error(body.error ?? `Durable Object request failed with ${res.status}`);
  }
  return body.data as T;
}

export async function fetchDynamicProbe(args: {
  baseUrl?: string;
  fetcher?: Fetcher;
  testId: string;
  runId: string;
}): Promise<ProbeResult | null> {
  if (!args.fetcher && !args.baseUrl) return null;
  const baseUrl = (args.baseUrl ?? "https://dynamic-parent.internal").replace(/\/+$/, "");
  const url = `${baseUrl}/probe/${args.testId}?run_id=${encodeURIComponent(args.runId)}`;
  const res = args.fetcher ? await args.fetcher.fetch(url) : await fetch(url);
  const body = (await res.json()) as ProbeResult & { error?: string; message?: string };
  if (!res.ok) {
    throw new Error(body.message ?? body.error ?? `Dynamic probe ${args.testId} failed with ${res.status}`);
  }
  return body;
}

export function delegatedResult(args: {
  dynamic: ProbeResult;
  testId: string;
  description: string;
  runId: string;
}): ProbeResult {
  return base({
    test_id: args.testId,
    track: "durable",
    description: args.description,
    result: args.dynamic.result,
    severity: args.dynamic.severity,
    run_id: args.runId,
    details: {
      delegated_to: args.dynamic.test_id,
      delegated_track: args.dynamic.track,
      delegated_timestamp: args.dynamic.timestamp,
      dynamic_details: args.dynamic.details,
    },
    comparison: args.dynamic.comparison,
  });
}
