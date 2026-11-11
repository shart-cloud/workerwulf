import { summarizeScript, WORKER_PARSE_LIMIT_BYTES } from "@wulf/analyze";
import {
  cfApiRest,
  collectNamespaces,
  collectScriptNames,
  collectScripts,
  coverageFromError,
  LIST_SCRIPTS_COVERAGE,
  type CfApi,
} from "@wulf/core";
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import * as Effect from "effect/Effect";
import type * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";

import { sanitizeBatch, type Batch } from "./batch.js";
import { hubFor, type Env } from "./env.js";
import type { CompleteResult } from "./store.js";

export interface ScanParams {
  /** Defaults to the deployment's `CLOUDFLARE_ACCOUNT_ID`. */
  accountId?: string;
}

/**
 * Scripts per step. Each script costs three API reads and at most one parse of
 * up to `WORKER_PARSE_LIMIT_BYTES`, so a step stays well inside a Worker's
 * memory and the API's 1,200 requests per 5 minutes.
 */
export const SCRIPTS_PER_STEP = 4;

const EMPTY: Batch = { scripts: [], namespaces: [], coverage: [] };

export function cfApiFor(env: Env, accountId: string): Layer.Layer<CfApi> {
  const stub = env.CF_API;
  return cfApiRest({
    accountId,
    token: Redacted.make(env.CLOUDFLARE_API_TOKEN ?? ""),
    ...(stub && { fetch: (url: string, init?: RequestInit) => stub.fetch(url, init) }),
  });
}

/**
 * One account scan. Steps: begin → list scripts → collect scripts in chunks →
 * collect namespaces → complete. Every collect step summarizes what it read and
 * appends it to ScanHub as one batch; bundle text never leaves the step.
 * Appends are idempotent on `(scan_id, batch_no)`, so step retries are safe.
 */
export class ScanWorkflow extends WorkflowEntrypoint<Env, ScanParams> {
  override async run(event: Readonly<WorkflowEvent<ScanParams>>, step: WorkflowStep) {
    const accountId = event.payload.accountId ?? this.env.CLOUDFLARE_ACCOUNT_ID;
    const scanId = event.instanceId;
    const hub = hubFor(this.env, accountId);
    const api = cfApiFor(this.env, accountId);
    const run = <A>(effect: Effect.Effect<A, never, CfApi>) => Effect.runPromise(Effect.provide(effect, api));

    await step.do("begin", async () => {
      await hub.begin(scanId, accountId, event.timestamp.toISOString(), "workflow");
      return scanId;
    });

    // Only the script list is fatal. Its failure is recorded, and the scan completes as `failed`.
    const names = await step.do("list scripts", async () => {
      const listed = await run(Effect.result(collectScriptNames));
      if (listed._tag === "Failure") {
        const coverage = [coverageFromError("account", "listScripts", listed.failure)];
        await hub.append(scanId, 0, { ...EMPTY, coverage });
        return null;
      }
      await hub.append(scanId, 0, { ...EMPTY, coverage: [LIST_SCRIPTS_COVERAGE] });
      return [...listed.success];
    });

    if (names !== null) {
      const chunks = chunk(names, SCRIPTS_PER_STEP);
      for (const [i, part] of chunks.entries()) {
        const batchNo = i + 1;
        await step.do(`collect scripts ${batchNo}/${chunks.length}`, async () => {
          const collected = await run(collectScripts(part));
          const summarized = collected.scripts.map((s) =>
            summarizeScript(s, { maxParseLength: WORKER_PARSE_LIMIT_BYTES }),
          );
          const batch: Batch = {
            scripts: summarized.map((s) => s.summary),
            namespaces: [],
            coverage: [...collected.coverage, ...summarized.flatMap((s) => s.coverage)],
          };
          await hub.append(scanId, batchNo, batch);
          return { batchNo, scripts: part.length };
        });
      }

      await step.do("collect namespaces", async () => {
        const collected = await run(collectNamespaces());
        const batch = sanitizeBatch({ ...EMPTY, namespaces: collected.namespaces, coverage: collected.coverage });
        await hub.append(scanId, chunks.length + 1, batch);
        return { batchNo: chunks.length + 1, namespaces: batch.namespaces.length };
      });
    }

    return await step.do("complete", async (): Promise<CompleteResult> => {
      const result: CompleteResult = await hub.complete(scanId, new Date().toISOString());
      return result;
    });
  }
}

function chunk<T>(items: ReadonlyArray<T>, size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}
