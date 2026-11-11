import { analyzeSummary, type AccountSummary, type Finding } from "@wulf/analyze";
import { findingKey, SEVERITY_ORDER, type Coverage, type Severity } from "@wulf/core";

import type { Batch } from "./batch.js";
import { bindingRef, coverageTarget, namespaceRef, resourceRef, scriptRef } from "./refs.js";

/** The slice of `DurableObjectStorage` the store needs, so tests can hand it any SQLite. */
export interface SqlHost {
  readonly sql: SqlStorage;
  transactionSync<T>(fn: () => T): T;
}

export type ScanStatus = "running" | "complete" | "partial" | "failed";
export type FindingState = "open" | "resolved" | "suppressed";

export interface ScanRecord {
  scan_id: string;
  account_id: string;
  source: string;
  started_at: string;
  completed_at: string | null;
  status: ScanStatus;
  result: CompleteResult | null;
  exported_at: string | null;
}

export interface CompleteResult {
  scan_id: string;
  status: ScanStatus;
  /** Findings this scan saw, by key. */
  seen: number;
  /** Seen for the first time. */
  opened: number;
  /** Were resolved, and are back. */
  reopened: number;
  resolved: number;
  /** Open findings not seen, but kept open because their reads didn't complete. */
  kept: number;
  /** Rules that threw; their findings are never resolved by this scan. */
  rule_errors: Array<{ rule_id: string; message: string }>;
}

export type FindingRecord = {
  key: string;
  rule_id: string;
  probe: string;
  family: string;
  severity: Severity;
  resource: string;
  ref: string;
  title: string;
  state: FindingState;
  first_seen: string;
  last_seen: string;
  last_scan_id: string;
  resolved_at: string | null;
  suppressed_reason: string | null;
};

export interface Occurrence {
  finding_key: string;
  scan_id: string;
  message: string;
  remediation: string;
  evidence: Finding["evidence"] | null;
  /** Times the rule reported this key in the scan. */
  count: number;
}

/**
 * Schema versions, applied in order and recorded in `_migrations`.
 * §7 of POSTURE_PLAN.md, plus: the account and source on each scan, the
 * human-readable `resource` beside each finding's ref, and export bookkeeping.
 */
const MIGRATIONS: ReadonlyArray<string> = [
  `
  CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, source TEXT NOT NULL,
    started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL,
    result TEXT, exported_at TEXT);
  CREATE TABLE batches (
    scan_id TEXT NOT NULL, batch_no INTEGER NOT NULL, payload TEXT NOT NULL, received_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, batch_no));
  CREATE TABLE observations (
    scan_id TEXT NOT NULL, ref TEXT NOT NULL, kind TEXT NOT NULL, attrs TEXT NOT NULL,
    PRIMARY KEY (scan_id, ref));
  CREATE TABLE edges (
    scan_id TEXT NOT NULL, from_ref TEXT NOT NULL, to_ref TEXT NOT NULL, kind TEXT NOT NULL,
    PRIMARY KEY (scan_id, from_ref, to_ref, kind));
  CREATE TABLE coverage (
    scan_id TEXT NOT NULL, seq INTEGER NOT NULL, target TEXT NOT NULL, op TEXT NOT NULL,
    status TEXT NOT NULL, detail TEXT, PRIMARY KEY (scan_id, seq));
  CREATE TABLE findings (
    key TEXT PRIMARY KEY, rule_id TEXT NOT NULL, probe TEXT NOT NULL, family TEXT NOT NULL,
    severity TEXT NOT NULL, resource TEXT NOT NULL, ref TEXT NOT NULL, title TEXT NOT NULL,
    state TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_scan_id TEXT NOT NULL,
    resolved_at TEXT, suppressed_reason TEXT);
  CREATE INDEX findings_state ON findings (state);
  CREATE TABLE occurrences (
    finding_key TEXT NOT NULL, scan_id TEXT NOT NULL, message TEXT NOT NULL, remediation TEXT NOT NULL,
    evidence TEXT, count INTEGER NOT NULL, PRIMARY KEY (finding_key, scan_id));
  CREATE INDEX occurrences_scan ON occurrences (scan_id);
  `,
];

/** Scans whose observations, edges, coverage and occurrences stay in SQLite. Older ones live in R2. */
export const DEFAULT_KEEP_SCANS = 10;

export class ScanNotFound extends Error {
  constructor(readonly scanId: string) {
    super(`unknown scan ${scanId}`);
  }
}

/**
 * ScanHub's SQLite: the batch write-ahead log, the folded scan, and the findings
 * lifecycle. Synchronous, as Durable Object SQLite is; every write method runs
 * in one transaction, so a retried Workflow step never sees half a write.
 */
export class HubStore {
  constructor(private readonly host: SqlHost) {}

  private get sql() {
    return this.host.sql;
  }

  migrate(): void {
    this.sql.exec("CREATE TABLE IF NOT EXISTS _migrations (version INTEGER PRIMARY KEY)");
    const row = this.sql.exec<{ v: number | null }>("SELECT MAX(version) AS v FROM _migrations").one();
    const applied = row.v ?? 0;
    for (let v = applied + 1; v <= MIGRATIONS.length; v++) {
      this.host.transactionSync(() => {
        this.sql.exec(MIGRATIONS[v - 1]!);
        this.sql.exec("INSERT INTO _migrations (version) VALUES (?)", v);
      });
    }
  }

  /** Start a scan. Idempotent: beginning a scan that exists changes nothing. */
  begin(scanId: string, accountId: string, startedAt: string, source: string): ScanRecord {
    this.sql.exec(
      `INSERT INTO scans (scan_id, account_id, source, started_at, status) VALUES (?, ?, ?, ?, 'running')
       ON CONFLICT (scan_id) DO NOTHING`,
      scanId,
      accountId,
      source,
      startedAt,
    );
    return this.requireScan(scanId);
  }

  /**
   * Add one batch to a running scan. Idempotent on `(scan_id, batch_no)`: a
   * retried step's second write is dropped. Returns false once the scan is done.
   */
  append(scanId: string, batchNo: number, batch: Batch, receivedAt: string): boolean {
    const scan = this.requireScan(scanId);
    if (scan.status !== "running") return false;
    this.sql.exec(
      `INSERT INTO batches (scan_id, batch_no, payload, received_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (scan_id, batch_no) DO NOTHING`,
      scanId,
      batchNo,
      JSON.stringify(batch),
      receivedAt,
    );
    return true;
  }

  /** The scan's batches joined in order: what was collected. */
  summary(scanId: string): AccountSummary {
    const scan = this.requireScan(scanId);
    const batches = this.sql
      .exec<{ payload: string }>("SELECT payload FROM batches WHERE scan_id = ? ORDER BY batch_no", scanId)
      .toArray()
      .map((r) => JSON.parse(r.payload) as Batch);
    return {
      accountId: scan.account_id,
      scripts: batches.flatMap((b) => b.scripts),
      namespaces: batches.flatMap((b) => b.namespaces),
      coverage: batches.flatMap((b) => b.coverage),
    };
  }

  /**
   * Fold the batches into observations, edges and coverage, run every account
   * rule, and update the findings lifecycle. Idempotent: completing a finished
   * scan returns its stored result.
   *
   * - A scan whose script list didn't complete is `failed` and changes no finding.
   * - A scan with any `failed` read is `partial` and resolves nothing.
   * - Otherwise an open finding that wasn't seen is resolved, unless a read it
   *   depends on was denied or unavailable, or its rule threw.
   */
  complete(scanId: string, completedAt: string): CompleteResult {
    const existing = this.requireScan(scanId);
    if (existing.status !== "running" && existing.result) return existing.result;

    return this.host.transactionSync(() => {
      const summary = this.summary(scanId);
      const account = summary.accountId;
      this.writeInventory(scanId, summary);

      const listed = summary.coverage.find((c) => c.target === "account" && c.op === "listScripts");
      const status: ScanStatus =
        listed?.status !== "complete"
          ? "failed"
          : summary.coverage.some((c) => c.status === "failed")
            ? "partial"
            : "complete";

      const result: CompleteResult = {
        scan_id: scanId,
        status,
        seen: 0,
        opened: 0,
        reopened: 0,
        resolved: 0,
        kept: 0,
        rule_errors: [],
      };

      if (status !== "failed") {
        const analysis = analyzeSummary(summary, { severity: "informational" });
        result.rule_errors = analysis.errors;
        const found = groupByKey(analysis.groups.flatMap((g) => g.findings));
        this.recordFindings(scanId, account, completedAt, found, result);
        if (status === "complete") this.resolveUnseen(completedAt, summary.coverage, found, result);
      }

      this.sql.exec(
        "UPDATE scans SET completed_at = ?, status = ?, result = ? WHERE scan_id = ?",
        completedAt,
        status,
        JSON.stringify(result),
        scanId,
      );
      return result;
    });
  }

  private writeInventory(scanId: string, summary: AccountSummary): void {
    const account = summary.accountId;
    const observe = (ref: string, kind: string, attrs: unknown) =>
      this.sql.exec(
        "INSERT OR REPLACE INTO observations (scan_id, ref, kind, attrs) VALUES (?, ?, ?, ?)",
        scanId,
        ref,
        kind,
        JSON.stringify(attrs),
      );
    const edge = (from: string, to: string, kind: string) =>
      this.sql.exec(
        "INSERT OR IGNORE INTO edges (scan_id, from_ref, to_ref, kind) VALUES (?, ?, ?, ?)",
        scanId,
        from,
        to,
        kind,
      );

    for (const script of summary.scripts) {
      const ref = scriptRef(account, script.name);
      observe(ref, "worker", script);
      for (const b of script.bindings ?? []) {
        const to = bindingRef(account, script.name, b.name);
        observe(to, "binding", b);
        edge(ref, to, "binds");
      }
    }
    for (const ns of summary.namespaces) {
      const ref = namespaceRef(account, ns.name);
      observe(ref, "dispatch_namespace", ns);
      for (const s of ns.scripts ?? []) edge(ref, scriptRef(account, s.name), "uses");
    }
    this.sql.exec("DELETE FROM coverage WHERE scan_id = ?", scanId);
    summary.coverage.forEach((c, seq) =>
      this.sql.exec(
        "INSERT INTO coverage (scan_id, seq, target, op, status, detail) VALUES (?, ?, ?, ?, ?, ?)",
        scanId,
        seq,
        c.target,
        c.op,
        c.status,
        c.detail ?? null,
      ),
    );
  }

  private recordFindings(
    scanId: string,
    account: string,
    at: string,
    found: ReadonlyMap<string, { finding: Finding; count: number }>,
    result: CompleteResult,
  ): void {
    const before = new Map(
      this.sql
        .exec<{ key: string; state: FindingState }>("SELECT key, state FROM findings")
        .toArray()
        .map((r) => [r.key, r.state] as const),
    );
    for (const [key, { finding: f, count }] of found) {
      const prior = before.get(key);
      if (prior === undefined) result.opened++;
      else if (prior === "resolved") result.reopened++;
      this.sql.exec(
        `INSERT INTO findings (key, rule_id, probe, family, severity, resource, ref, title, state,
                               first_seen, last_seen, last_scan_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
         ON CONFLICT (key) DO UPDATE SET
           probe = excluded.probe, family = excluded.family, severity = excluded.severity,
           ref = excluded.ref, title = excluded.title,
           last_seen = excluded.last_seen, last_scan_id = excluded.last_scan_id,
           state = CASE WHEN findings.state = 'suppressed' THEN 'suppressed' ELSE 'open' END,
           resolved_at = CASE WHEN findings.state = 'suppressed' THEN findings.resolved_at ELSE NULL END`,
        key,
        f.rule_id,
        f.probe,
        f.family,
        f.severity,
        f.resource,
        resourceRef(account, f.resource),
        f.title,
        at,
        at,
        scanId,
      );
      this.sql.exec(
        `INSERT OR REPLACE INTO occurrences (finding_key, scan_id, message, remediation, evidence, count)
         VALUES (?, ?, ?, ?, ?, ?)`,
        key,
        scanId,
        f.message,
        f.remediation,
        f.evidence ? JSON.stringify(f.evidence) : null,
        count,
      );
    }
    result.seen = found.size;
  }

  private resolveUnseen(
    at: string,
    coverage: ReadonlyArray<Coverage>,
    found: ReadonlyMap<string, unknown>,
    result: CompleteResult,
  ): void {
    const incomplete = new Set(coverage.filter((c) => c.status !== "complete").map((c) => c.target));
    const errored = new Set(result.rule_errors.map((e) => e.rule_id));
    const open = this.sql
      .exec<{ key: string; rule_id: string; resource: string }>(
        "SELECT key, rule_id, resource FROM findings WHERE state = 'open'",
      )
      .toArray();
    for (const f of open) {
      if (found.has(f.key)) continue;
      const target = coverageTarget(f.resource);
      // Namespace findings also depend on the account-level namespace listing.
      const blind =
        incomplete.has(target) || (target.startsWith("namespace:") && incomplete.has("account"));
      if (blind || errored.has(f.rule_id)) {
        result.kept++;
        continue;
      }
      this.sql.exec(
        "UPDATE findings SET state = 'resolved', resolved_at = ? WHERE key = ?",
        at,
        f.key,
      );
      result.resolved++;
    }
  }

  /** Suppress a finding; it stays suppressed through later scans until unsuppressed. */
  suppress(key: string, reason: string): FindingRecord | undefined {
    this.sql.exec("UPDATE findings SET state = 'suppressed', suppressed_reason = ? WHERE key = ?", reason, key);
    return this.finding(key);
  }

  /** Lift a suppression. The finding is open again until a complete scan doesn't see it. */
  unsuppress(key: string): FindingRecord | undefined {
    this.sql.exec(
      "UPDATE findings SET state = 'open', suppressed_reason = NULL WHERE key = ? AND state = 'suppressed'",
      key,
    );
    return this.finding(key);
  }

  finding(key: string): FindingRecord | undefined {
    return this.sql.exec<FindingRecord>("SELECT * FROM findings WHERE key = ?", key).toArray()[0];
  }

  findings(state?: FindingState): FindingRecord[] {
    const rows =
      state === undefined
        ? this.sql.exec<FindingRecord>("SELECT * FROM findings")
        : this.sql.exec<FindingRecord>("SELECT * FROM findings WHERE state = ?", state);
    return rows.toArray().sort(compareFindings);
  }

  occurrences(scanId: string): Occurrence[] {
    return this.sql
      .exec<Omit<Occurrence, "evidence"> & { evidence: string | null }>(
        "SELECT * FROM occurrences WHERE scan_id = ? ORDER BY finding_key",
        scanId,
      )
      .toArray()
      .map((o) => ({ ...o, evidence: o.evidence ? (JSON.parse(o.evidence) as Finding["evidence"]) : null }));
  }

  coverage(scanId: string): Coverage[] {
    return this.sql
      .exec<{ target: string; op: string; status: Coverage["status"]; detail: string | null }>(
        "SELECT target, op, status, detail FROM coverage WHERE scan_id = ? ORDER BY seq",
        scanId,
      )
      .toArray()
      .map((c) => ({ target: c.target, op: c.op, status: c.status, ...(c.detail !== null && { detail: c.detail }) }));
  }

  scan(scanId: string): ScanRecord | undefined {
    const row = this.sql
      .exec<Omit<ScanRecord, "result"> & { result: string | null }>("SELECT * FROM scans WHERE scan_id = ?", scanId)
      .toArray()[0];
    return row && { ...row, result: row.result ? (JSON.parse(row.result) as CompleteResult) : null };
  }

  scans(limit = 20): ScanRecord[] {
    return this.sql
      .exec<{ scan_id: string }>("SELECT scan_id FROM scans ORDER BY started_at DESC, scan_id DESC LIMIT ?", limit)
      .toArray()
      .map((r) => this.scan(r.scan_id)!);
  }

  /** Finished scans not yet written to R2, oldest first. */
  unexported(): ScanRecord[] {
    return this.sql
      .exec<{ scan_id: string }>(
        "SELECT scan_id FROM scans WHERE status != 'running' AND exported_at IS NULL ORDER BY started_at, scan_id",
      )
      .toArray()
      .map((r) => this.scan(r.scan_id)!);
  }

  /** One scan's history files, as JSONL text per file name. */
  exportFiles(scanId: string): Record<string, string> {
    const jsonl = (rows: unknown[]) => rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : "");
    const observations = this.sql
      .exec<{ ref: string; kind: string; attrs: string }>(
        "SELECT ref, kind, attrs FROM observations WHERE scan_id = ? ORDER BY ref",
        scanId,
      )
      .toArray()
      .map((o) => ({ ref: o.ref, kind: o.kind, attrs: JSON.parse(o.attrs) as unknown }));
    const edges = this.sql
      .exec("SELECT from_ref, to_ref, kind FROM edges WHERE scan_id = ? ORDER BY from_ref, to_ref, kind", scanId)
      .toArray();
    const occurrences = new Map(this.occurrences(scanId).map((o) => [o.finding_key, o]));
    const findings = this.findings()
      .filter((f) => occurrences.has(f.key))
      .map((f) => {
        const o = occurrences.get(f.key)!;
        return { ...f, message: o.message, remediation: o.remediation, evidence: o.evidence, count: o.count };
      });
    return {
      "scan.json": JSON.stringify(this.scan(scanId)) + "\n",
      "observations.jsonl": jsonl(observations),
      "edges.jsonl": jsonl(edges),
      "coverage.jsonl": jsonl(this.coverage(scanId)),
      "findings.jsonl": jsonl(findings),
    };
  }

  /**
   * After a scan reaches R2: drop its batches, and keep observations, edges,
   * coverage and occurrences for only the newest `keep` scans. A finding's
   * latest occurrence is always kept.
   */
  markExported(scanId: string, at: string, keep = DEFAULT_KEEP_SCANS): void {
    this.host.transactionSync(() => {
      this.sql.exec("UPDATE scans SET exported_at = ? WHERE scan_id = ?", at, scanId);
      this.sql.exec("DELETE FROM batches WHERE scan_id = ?", scanId);
      const old = this.sql
        .exec<{ scan_id: string }>(
          "SELECT scan_id FROM scans WHERE status != 'running' ORDER BY started_at DESC, scan_id DESC LIMIT -1 OFFSET ?",
          keep,
        )
        .toArray()
        .map((r) => r.scan_id);
      for (const id of old) {
        this.sql.exec("DELETE FROM observations WHERE scan_id = ?", id);
        this.sql.exec("DELETE FROM edges WHERE scan_id = ?", id);
        this.sql.exec("DELETE FROM coverage WHERE scan_id = ?", id);
        this.sql.exec(
          `DELETE FROM occurrences WHERE scan_id = ?
             AND finding_key NOT IN (SELECT key FROM findings WHERE last_scan_id = ?)`,
          id,
          id,
        );
      }
    });
  }

  /** Rows in a table, for tests and the sentinel check. */
  dump(table: "batches" | "observations" | "edges" | "coverage" | "findings" | "occurrences" | "scans"): unknown[] {
    return this.sql.exec(`SELECT * FROM ${table}`).toArray();
  }

  private requireScan(scanId: string): ScanRecord {
    const scan = this.scan(scanId);
    if (!scan) throw new ScanNotFound(scanId);
    return scan;
  }
}

/** Findings by key. A rule that reports the same key twice in one scan counts as one finding. */
function groupByKey(findings: ReadonlyArray<Finding>): Map<string, { finding: Finding; count: number }> {
  const out = new Map<string, { finding: Finding; count: number }>();
  for (const f of findings) {
    const key = findingKey(f);
    const seen = out.get(key);
    if (seen) seen.count++;
    else out.set(key, { finding: f, count: 1 });
  }
  return out;
}

const compareFindings = (a: FindingRecord, b: FindingRecord): number =>
  SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
  (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0) ||
  (a.resource < b.resource ? -1 : a.resource > b.resource ? 1 : 0);
