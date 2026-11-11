import type { ScanHub } from "./hub.js";
import type { ScanParams } from "./workflow.js";

export interface Env {
  SCAN_HUB: DurableObjectNamespace<ScanHub>;
  SCAN_WORKFLOW: Workflow<ScanParams>;
  /** Scan history: `history/<scan_id>/*.jsonl`. */
  HISTORY: R2Bucket;
  /** The account this deployment scans. One deployment per account. */
  CLOUDFLARE_ACCOUNT_ID: string;
  /** Read-only API token for collection (secret). */
  CLOUDFLARE_API_TOKEN?: string;
  /** Bearer token for every HTTP request (secret). Unset means every request is refused. */
  WULF_TOKEN?: string;
  /** Scans whose detail stays in SQLite; older scans live only in R2. Default 10. */
  KEEP_SCANS?: string;
  /** Tests only: a stand-in for api.cloudflare.com. */
  CF_API?: Fetcher;
}

/** The account's ScanHub. One Durable Object per account, named by account id. */
export const hubFor = (env: Env, accountId: string) => env.SCAN_HUB.get(env.SCAN_HUB.idFromName(accountId));
