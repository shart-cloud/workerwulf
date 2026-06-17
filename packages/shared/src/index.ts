export type Track = "worker" | "dynamic" | "durable" | "ai" | "platform" | "astro";

export type Verdict =
  | "accessible"
  | "blocked"
  | "partial"
  | "error"
  | "informational";

export type ComparisonPlatform =
  | "aws_lambda"
  | "azure_functions"
  | "gcp_functions";

export interface ProbeResult {
  test_id: string;
  track: Track;
  timestamp: string;
  description: string;
  target?: string;
  result: Verdict;
  details: Record<string, unknown>;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  comparison?: Partial<Record<ComparisonPlatform, string>>;
  run_id?: string;
}

export interface ProbeRequest {
  run_id?: string;
  params?: Record<string, unknown>;
}

export {
  buildCallbackHttpTarget,
  buildControlledHostname,
  forceHttps,
} from "./callbacks.js";
