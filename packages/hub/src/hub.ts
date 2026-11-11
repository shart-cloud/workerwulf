import { DurableObject } from "cloudflare:workers";

import type { Batch } from "./batch.js";
import type { Env } from "./env.js";
import { DEFAULT_KEEP_SCANS, HubStore, type FindingState } from "./store.js";

/**
 * ScanHub: one per account. Holds the batch write-ahead log, the folded scans
 * and the findings lifecycle in SQLite, and exports finished scans to R2 from
 * its alarm.
 */
export class ScanHub extends DurableObject<Env> {
  private readonly store: HubStore;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.store = new HubStore(ctx.storage);
    ctx.blockConcurrencyWhile(async () => this.store.migrate());
  }

  begin(scanId: string, accountId: string, startedAt: string, source: string) {
    return this.store.begin(scanId, accountId, startedAt, source);
  }

  append(scanId: string, batchNo: number, batch: Batch): boolean {
    return this.store.append(scanId, batchNo, batch, new Date().toISOString());
  }

  async complete(scanId: string, completedAt: string) {
    const result = this.store.complete(scanId, completedAt);
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now());
    return result;
  }

  findings(state?: FindingState) {
    return this.store.findings(state);
  }

  suppress(key: string, reason: string) {
    return this.store.suppress(key, reason);
  }

  unsuppress(key: string) {
    return this.store.unsuppress(key);
  }

  scan(scanId: string) {
    const scan = this.store.scan(scanId);
    return scan && { ...scan, coverage: this.store.coverage(scanId) };
  }

  scans(limit?: number) {
    return this.store.scans(limit);
  }

  occurrences(scanId: string) {
    return this.store.occurrences(scanId);
  }

  /** Write each finished, unexported scan to R2, then prune what R2 now holds. */
  override async alarm(): Promise<void> {
    const keep = Number(this.env.KEEP_SCANS) || DEFAULT_KEEP_SCANS;
    for (const scan of this.store.unexported()) {
      const files = this.store.exportFiles(scan.scan_id);
      for (const [name, body] of Object.entries(files)) {
        await this.env.HISTORY.put(`history/${scan.scan_id}/${name}`, body, {
          httpMetadata: { contentType: name.endsWith(".json") ? "application/json" : "application/x-ndjson" },
        });
      }
      this.store.markExported(scan.scan_id, new Date().toISOString(), keep);
    }
  }
}
