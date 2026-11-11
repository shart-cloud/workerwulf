import * as Schema from "effect/Schema";

import type { CfError } from "../cf/errors.js";

/**
 * What a collection step could see. A read that wasn't `complete` means the
 * related rules ran on partial data — never that the resource is clean.
 */
export const CoverageStatus = Schema.Literals(["complete", "denied", "unavailable", "failed"]);
export type CoverageStatus = typeof CoverageStatus.Type;

export const Coverage = Schema.Struct({
  /** What was read: "account", "script:prey", "namespace:tenants". */
  target: Schema.String,
  /** Which read: "listScripts", "bindings", "content", "routes", "namespace". */
  op: Schema.String,
  status: CoverageStatus,
  detail: Schema.optionalKey(Schema.String),
});
export type Coverage = typeof Coverage.Type;

export const coverageFromError = (target: string, op: string, error: CfError): Coverage => {
  switch (error._tag) {
    case "PermissionDenied":
      return { target, op, status: "denied", detail: `HTTP ${error.status} on ${error.path}` };
    case "NotFound":
      return { target, op, status: "unavailable", detail: `HTTP 404 on ${error.path}` };
    case "RateLimited":
      return { target, op, status: "failed", detail: `rate limited on ${error.path}` };
    case "ApiError":
      return { target, op, status: "failed", detail: `${error.path}: ${error.message}` };
  }
};

/** True when nothing failed outright; denied/unavailable reads are expected gaps. */
export const isComplete = (coverage: ReadonlyArray<Coverage>): boolean =>
  coverage.every((c) => c.status !== "failed");
