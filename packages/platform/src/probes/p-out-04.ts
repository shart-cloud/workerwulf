import type { Probe } from "./index.js";
import { base, invokeTenant, namespaceMode, outboundLogEvents } from "./_helpers.js";

export const pOut04: Probe = async (c) => {
  const mode = namespaceMode(c.req);
  const target = c.env.WULF_ALLOWED_TEST_URL ?? "https://cloudflare.com/cdn-cgi/trace";
  const resp = await invokeTenant<Record<string, unknown>>(c, "tenant-prey", "spoof-fetch", { target }, { mode });
  const events = await outboundLogEvents(c.env, "P-OUT-04", c.runId);
  const attributedCustomers = [...new Set(events.map((event) => event.customer_name).filter(Boolean))];
  const policyConfusionAchieved = attributedCustomers.some((name) => name !== "tenant-prey");

  return base({
    test_id: "P-OUT-04",
    track: "platform",
    description: "Outbound Worker identity and parameter confusion resistance",
    result: policyConfusionAchieved ? "accessible" : "blocked",
    severity: policyConfusionAchieved ? "high" : "medium",
    run_id: c.runId,
    details: {
      namespace: mode,
      true_customer: "tenant-prey",
      spoof_vectors: ["x-wulf-customer-name", "x-forwarded-host", "x-forwarded-for", "cf-connecting-ip"],
      target,
      user_worker_fetch: resp.body,
      outbound_attributed_customers: attributedCustomers,
      policy_confusion_achieved: policyConfusionAchieved,
      outbound_events: events,
      note: "A safe outbound policy keys tenant identity from dispatcher-provided env, not request-derived headers.",
    },
  });
};
