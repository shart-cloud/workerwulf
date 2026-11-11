import * as Schema from "effect/Schema";

import { Severity } from "./finding.js";

export const Track = Schema.Literals(["worker", "dynamic", "durable", "ai", "platform", "astro"]);
export type Track = typeof Track.Type;

export const Verdict = Schema.Literals(["accessible", "blocked", "partial", "error", "informational"]);
export type Verdict = typeof Verdict.Type;

export const ComparisonPlatform = Schema.Literals(["aws_lambda", "azure_functions", "gcp_functions"]);
export type ComparisonPlatform = typeof ComparisonPlatform.Type;

/**
 * The research harness's result record. Mirrors `ProbeResult` in `@wulf/shared`
 * (the probe Workers keep their plain interface; a type test keeps the two in step).
 */
export const ProbeResult = Schema.Struct({
  test_id: Schema.String,
  track: Track,
  timestamp: Schema.String,
  description: Schema.String,
  target: Schema.optionalKey(Schema.String),
  result: Verdict,
  details: Schema.Record(Schema.String, Schema.Unknown),
  severity: Severity,
  comparison: Schema.optionalKey(
    Schema.Struct({
      aws_lambda: Schema.optionalKey(Schema.String),
      azure_functions: Schema.optionalKey(Schema.String),
      gcp_functions: Schema.optionalKey(Schema.String),
    }),
  ),
  run_id: Schema.optionalKey(Schema.String),
  tags: Schema.optionalKey(Schema.Array(Schema.String)),
});
export type ProbeResult = typeof ProbeResult.Type;
