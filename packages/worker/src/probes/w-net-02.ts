import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

const METADATA_TARGETS = [
  { platform: "aws", url: "http://169.254.169.254/latest/meta-data/" },
  { platform: "aws_imdsv2_token", url: "http://169.254.169.254/latest/api/token" },
  { platform: "gcp", url: "http://metadata.google.internal/computeMetadata/v1/" },
  { platform: "azure", url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01" },
  { platform: "alibaba", url: "http://100.100.100.200/latest/meta-data/" },
];

export const wNet02: Probe = async ({ runId }) => {
  const probes = await Promise.all(
    METADATA_TARGETS.map(async ({ platform, url }) => {
      const started = Date.now();
      try {
        const res = await fetch(url, {
          headers: {
            "metadata-flavor": "Google",
            metadata: "true",
            "x-aws-ec2-metadata-token-ttl-seconds": "60",
          },
          signal: AbortSignal.timeout(2000),
        });
        const bodyPreview = (await res.text()).slice(0, 256);
        const metadataRetrieved = isMetadataResponse(platform, res.status, bodyPreview);
        const blockedByPlatformError = isCloudflareNetworkError(res.status, bodyPreview);
        return {
          platform,
          url,
          request_completed: true,
          http_status: res.status,
          latency_ms: Date.now() - started,
          body_preview: bodyPreview,
          metadata_retrieved: metadataRetrieved,
          blocked_by_platform_error: blockedByPlatformError,
        };
      } catch (err) {
        return {
          platform,
          url,
          request_completed: false,
          metadata_retrieved: false,
          blocked_by_platform_error: false,
          latency_ms: Date.now() - started,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    }),
  );

  const anyMetadataRetrieved = probes.some((p) => p.metadata_retrieved);

  return base({
    test_id: "W-NET-02",
    track: "worker",
    description: "Cloud metadata endpoint retrieval probes",
    result: anyMetadataRetrieved ? "accessible" : "blocked",
    severity: anyMetadataRetrieved ? "high" : "informational",
    run_id: runId,
    details: { probes },
    comparison: {
      aws_lambda: "accessible (IMDSv1 default in legacy runtimes)",
      azure_functions: "accessible",
      gcp_functions: "accessible (metadata.google.internal)",
    },
  });
};

function isCloudflareNetworkError(status: number, body: string): boolean {
  return (status === 403 && body.includes("error code: 1003"))
    || (status === 530 && body.includes("error code: 1016"));
}

function isMetadataResponse(platform: string, status: number, body: string): boolean {
  if (status < 200 || status >= 300) return false;
  if (isCloudflareNetworkError(status, body)) return false;
  const lower = body.toLowerCase();
  if (platform.startsWith("aws")) return lower.includes("ami-") || lower.includes("instance-id") || lower.includes("security-credentials");
  if (platform === "gcp") return lower.includes("instance/") || lower.includes("project/") || lower.includes("metadata-flavor");
  if (platform === "azure") return lower.includes("compute") || lower.includes("subscriptionid") || lower.includes("vmid");
  if (platform === "alibaba") return lower.includes("instance-id") || lower.includes("ram/security-credentials");
  return false;
}
