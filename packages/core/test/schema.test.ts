import * as Schema from "effect/Schema";
import { describe, expect, expectTypeOf, it } from "vitest";

import type { ProbeResult as SharedProbeResult } from "@wulf/shared";

import { Finding, findingKey, ProbeResult } from "../src/index.js";

describe("schemas", () => {
  it("decodes a finding and keys it by rule and resource", () => {
    const f = Schema.decodeUnknownSync(Finding)({
      rule_id: "WF-BIND-01",
      title: "t",
      severity: "high",
      resource: "script:prey",
      message: "m",
      remediation: "r",
      probe: "W-CAP-01",
      family: "B",
    });
    expect(findingKey(f)).toBe("WF-BIND-01|script:prey");
  });

  it("rejects an unknown severity", () => {
    expect(() =>
      Schema.decodeUnknownSync(Finding)({
        rule_id: "x", title: "t", severity: "severe", resource: "r",
        message: "m", remediation: "r", probe: "p", family: "A",
      }),
    ).toThrow();
  });

  it("decodes a harness probe result", () => {
    const p = Schema.decodeUnknownSync(ProbeResult)({
      test_id: "W-ENV-01",
      track: "worker",
      timestamp: "2026-05-28T00:00:00Z",
      description: "globals",
      result: "accessible",
      details: { keys: 3 },
      severity: "informational",
      comparison: { aws_lambda: "env vars readable" },
      tags: ["misconfig"],
    });
    expect(p.test_id).toBe("W-ENV-01");
  });

  it("stays compatible with @wulf/shared's ProbeResult", () => {
    // Every result the probe Workers emit must decode into the core schema.
    expectTypeOf<SharedProbeResult>().toExtend<ProbeResult>();
  });
});
