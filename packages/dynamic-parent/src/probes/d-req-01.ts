import type { Probe } from "./index.js";
import { base, invokeChild, loadChild } from "./_helpers.js";

export const dReq01: Probe = async ({ env, runId }) => {
  // The parent constructs an arbitrary Request that it hands to the child.
  // Cloudflare normally synthesizes request.cf for *real* incoming traffic;
  // a parent-fabricated Request likely has no cf field at all. This probe
  // confirms whether the child sees any platform-injected metadata.
  const stub = loadChild(env, { env: {} });
  const { body } = await invokeChild(stub, "cf-dump");

  type Data = {
    cf_present: boolean;
    cf_type: string;
    cf_keys: string[];
    cf: Record<string, unknown>;
    cf_headers: Record<string, string>;
  };
  const data = (body as { ok: boolean; data: Data }).data;

  const visible = data.cf_present && data.cf_keys.length > 0;

  return base({
    test_id: "D-REQ-01",
    track: "dynamic",
    description: "Does the child see Cloudflare-injected request.cf metadata?",
    result: visible ? "accessible" : "blocked",
    severity: "informational",
    run_id: runId,
    details: {
      cf_present: data.cf_present,
      cf_type: data.cf_type,
      cf_field_count: data.cf_keys.length,
      cf_keys: data.cf_keys,
      cf_sample: data.cf,
      cf_headers: data.cf_headers,
    },
  });
};
