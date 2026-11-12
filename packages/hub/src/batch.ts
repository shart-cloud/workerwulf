import { Coverage } from "@wulf/core";
import type { RawNamespace } from "@wulf/core";
import type { ScriptSummary } from "@wulf/analyze";
import * as Schema from "effect/Schema";

/**
 * One write to ScanHub's write-ahead log: part of an account summary. A scan's
 * batches, joined in `batch_no` order, are its `AccountSummary`. Batches carry
 * derived data only, never bundle text or binding values.
 */
export interface Batch {
  readonly scripts: ReadonlyArray<ScriptSummary>;
  readonly namespaces: ReadonlyArray<RawNamespace>;
  readonly coverage: ReadonlyArray<Coverage>;
}

const NamedBinding = Schema.Struct({ type: Schema.String, name: Schema.String });

const ScriptSummarySchema = Schema.Struct({
  name: Schema.String,
  bindings: Schema.optionalKey(Schema.Array(NamedBinding)),
  routes: Schema.optionalKey(Schema.Array(Schema.String)),
  usage: Schema.optionalKey(
    Schema.Struct({ used: Schema.Array(Schema.String), envDestructured: Schema.Boolean }),
  ),
  contentLength: Schema.optionalKey(Schema.Number),
});

/**
 * Namespaces keep only what the rules read. `outbound` and `limits` become
 * `true` when set, so whatever config they held is never stored.
 */
const NamespaceSchema = Schema.Struct({
  name: Schema.String,
  trusted: Schema.optionalKey(Schema.Boolean),
  outbound: Schema.optionalKey(Schema.Unknown),
  limits: Schema.optionalKey(Schema.Unknown),
  scripts: Schema.optionalKey(
    Schema.Array(Schema.Struct({ name: Schema.String, untrusted: Schema.optionalKey(Schema.Boolean) })),
  ),
});

export const BatchSchema = Schema.Struct({
  scripts: Schema.Array(ScriptSummarySchema),
  namespaces: Schema.Array(NamespaceSchema),
  coverage: Schema.Array(Coverage),
});

/** Decode an untrusted batch (e.g. from `wulf scan --push`), dropping unknown keys. */
export const decodeBatch = (u: unknown): Batch => sanitizeBatch(Schema.decodeUnknownSync(BatchSchema)(u));

/** Reduce namespace config to flags, so no outbound or limits config is persisted. */
export const sanitizeBatch = (batch: Batch): Batch => ({
  scripts: batch.scripts,
  coverage: batch.coverage,
  namespaces: batch.namespaces.map((ns) => ({
    name: ns.name,
    ...(ns.trusted !== undefined && { trusted: ns.trusted }),
    ...(ns.outbound ? { outbound: true } : {}),
    ...(ns.limits ? { limits: true } : {}),
    ...(ns.scripts !== undefined && {
      scripts: ns.scripts.map((s) => ({ name: s.name, ...(s.untrusted !== undefined && { untrusted: s.untrusted }) })),
    }),
  })),
});
