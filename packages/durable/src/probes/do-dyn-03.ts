import type { Probe } from "./index.js";
import { base, delegatedResult, doFetch, fetchDynamicProbe } from "./_helpers.js";

export const doDyn03: Probe = async ({ env, runId }) => {
  const dynamic = await fetchDynamicProbe({
    baseUrl: env.WULF_DYNAMIC_BASE_URL,
    fetcher: env.DYNAMIC_PARENT,
    testId: "D-DO-03",
    runId,
  });
  if (dynamic) {
    return delegatedResult({
      dynamic,
      testId: "DO-DYN-03",
      description: "Cross-object access from Dynamic Worker sandbox",
      runId,
    });
  }

  // DO-DYN-03: Test cross-object access — can a Dynamic Worker reach a
  // different DO instance? We simulate by attempting to construct a DO
  // ID for a different name from the same namespace.
  const ns = env.PREY_DO;
  const originalId = ns.idFromName("DO-DYN-03-original");
  const guessedId = ns.idFromName("DO-DYN-03-other");

  const originalStub = ns.get(originalId);
  const guessedStub = ns.get(guessedId);

  await doFetch(originalStub, "http://do/init-schema");
  await doFetch(guessedStub, "http://do/init-schema");

  const markerUser = `marker-${runId}`.replace(/[^a-zA-Z0-9-]/g, "-");
  const markerPayload = `admin'; INSERT INTO users (username, password, secret) VALUES ('${markerUser}', 'marker', 'do-dyn-03-marker'); SELECT * FROM users WHERE username = 'admin`;
  await doFetch(
    originalStub,
    `http://do/stacked-query?input=${encodeURIComponent(markerPayload)}`,
  );

  // Try to read the original object's marker from the guessed object.
  const data = await doFetch<{ rows?: unknown[] }>(
    guessedStub,
    `http://do/classic-sqli?input=${encodeURIComponent(markerUser)}`,
  );
  const rows = data.rows ?? [];

  const crossAccess = rows.length > 0;

  return base({
    test_id: "DO-DYN-03",
    track: "durable",
    description: "Cross-object access from Dynamic Worker sandbox",
    result: "partial",
    severity: crossAccess ? "high" : "informational",
    run_id: runId,
    details: {
      original_id: originalId.toString(),
      guessed_id: guessedId.toString(),
      ids_equal: originalId.toString() === guessedId.toString(),
      marker_user: markerUser,
      cross_access_possible: crossAccess,
      note: "Partial only: this baseline uses parent access to the namespace. Configure WULF_DYNAMIC_BASE_URL to delegate to packages/dynamic-parent D-DO-03.",
    },
    comparison: {
      aws_lambda: "N/A",
      azure_functions: "N/A",
      gcp_functions: "N/A",
    },
  });
};
