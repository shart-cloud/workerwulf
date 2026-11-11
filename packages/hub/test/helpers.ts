import { env } from "cloudflare:workers";
import { introspectWorkflowInstance } from "cloudflare:test";

import type { CompleteResult } from "../src/store.js";

export interface FakeScript {
  bindings?: Array<Record<string, unknown>>;
  routes?: string[];
  content?: string;
  fail?: { settings?: number; routes?: number; content?: number };
}

export interface FakeAccount {
  scripts: Record<string, FakeScript>;
  namespaces?: Record<string, Record<string, unknown>>;
  fail?: { list?: number; namespaces?: number };
}

/** Text that must never reach SQLite or R2: a plain_text binding value and a bundle string. */
export const SENTINEL_VALUE = "sentinel-binding-value-7f3a";
export const SENTINEL_BUNDLE = "sentinel-bundle-text-91c2";

export const PREY_CONTENT =
  `const banner = "${SENTINEL_BUNDLE}";\n` +
  "export default { fetch(req, env) { return new Response(banner + env.HYPERDRIVE.connectionString + env.API_TOKEN); } };";

/**
 * The analyze-poc canned account, served over HTTP:
 * - `prey`: unused KV (WF-PRIV-01), Hyperdrive on a public route (WF-PRIV-02);
 * - `locked`: bindings read denied, routes endpoint missing;
 * - `tenants`: a trusted dispatch namespace with no outbound Worker or limits.
 */
export const fixtureAccount = (): FakeAccount => ({
  scripts: {
    prey: {
      bindings: [
        { type: "hyperdrive", name: "HYPERDRIVE", id: "hd1" },
        { type: "kv_namespace", name: "UNUSED_KV", namespace_id: "kv1" },
        { type: "secret_text", name: "API_TOKEN" },
        { type: "plain_text", name: "GREETING", text: SENTINEL_VALUE },
      ],
      routes: ["prey.example.com/*"],
      content: PREY_CONTENT,
    },
    locked: { content: "export default { fetch() { return new Response('ok'); } };", fail: { settings: 403, routes: 404 } },
  },
  namespaces: { tenants: { trusted_workers: true, outbound: { worker: { service: "x", secret: SENTINEL_VALUE } } } },
});

export async function setAccount(account: FakeAccount): Promise<void> {
  const res = await env.CF_API!.fetch("http://fake-cf/__state", { method: "POST", body: JSON.stringify(account) });
  if (!res.ok) throw new Error(`fake-cf: ${res.status}`);
}

export const hubOf = (accountId: string) => env.SCAN_HUB.get(env.SCAN_HUB.idFromName(accountId));

/** Run one ScanWorkflow instance to completion and return `complete`'s result. */
export async function runScan(accountId: string, scanId: string): Promise<CompleteResult> {
  await using instance = await introspectWorkflowInstance(env.SCAN_WORKFLOW, scanId);
  await env.SCAN_WORKFLOW.create({ id: scanId, params: { accountId } });
  await instance.waitForStatus("complete");
  return (await instance.getOutput()) as CompleteResult;
}

/** Every finding's identity and content, for comparing two sources. */
export const shape = (f: { rule_id: string; resource: string; severity: string; title: string }) =>
  `${f.severity} ${f.rule_id} ${f.resource} — ${f.title}`;
