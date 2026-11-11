import * as Data from "effect/Data";

/** 401/403: the token can't read this. Coverage, not absence. */
export class PermissionDenied extends Data.TaggedError("PermissionDenied")<{
  readonly path: string;
  readonly status: number;
}> {}

/** 404: the object or the endpoint doesn't exist for this account. */
export class NotFound extends Data.TaggedError("NotFound")<{
  readonly path: string;
}> {}

/** 429: rate limited. Retried by the REST layer before it surfaces. */
export class RateLimited extends Data.TaggedError("RateLimited")<{
  readonly path: string;
}> {}

/** Anything else: network failure, 5xx, malformed body, `success: false`. */
export class ApiError extends Data.TaggedError("ApiError")<{
  readonly path: string;
  readonly message: string;
  readonly status?: number;
}> {}

export type CfError = PermissionDenied | NotFound | RateLimited | ApiError;
