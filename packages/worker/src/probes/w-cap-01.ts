import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

/**
 * W-CAP-01 — Hyperdrive capability-binding blast radius (misconfig).
 *
 * The closest Cloudflare analog to Serverless Prey's central finding ("what
 * creds sit in the function's environment?"). A Worker bound to Hyperdrive can
 * read the full database connection — host, user, and password — straight off
 * `env.HYPERDRIVE`, then connect through it and read the backing Postgres.
 * Equivalent to an RDS connection string living in a Lambda's env. This probe
 * (1) reports what the binding exposes and (2) exfils the seeded canary rows.
 *
 * Deploy-only: requires the live HYPERDRIVE binding + the wulf-pg backing DB.
 * Locally (no binding) it returns `blocked`.
 */
export const wCap01: Probe = async ({ env, runId }) => {
  const hd = env.HYPERDRIVE;
  if (!hd) {
    return base({
      test_id: "W-CAP-01",
      track: "worker",
      description:
        "Hyperdrive capability binding — read DB credentials from the binding and exfil canary rows from the backing Postgres",
      target: "env.HYPERDRIVE",
      result: "blocked",
      severity: "informational",
      run_id: runId,
      tags: ["misconfig", "misconfig:binding"],
      details: {
        error: "HYPERDRIVE binding not present (expected locally / pre-deploy)",
      },
    });
  }

  // (1) The binding itself hands a compromised Worker full DB credentials.
  const exposed = {
    host: hd.host,
    port: hd.port,
    database: hd.database,
    user: hd.user,
    password_present: typeof hd.password === "string" && hd.password.length > 0,
    connection_string_present: typeof hd.connectionString === "string",
  };

  // (2) Use those credentials to read the backing database.
  let rows: Array<{ label: unknown; secret: unknown }> = [];
  let error: string | null = null;
  let canaryExfiltrated = false;
  try {
    // Lazy import: defers `postgres` (and its node:* deps) from module-eval to
    // first probe call, trimming the main worker's cold-start. (Does NOT make the
    // no-compat variant buildable — wrangler still bundles the lazy chunk.)
    const { default: postgres } = await import("postgres");
    const sql = postgres(hd.connectionString, {
      max: 5,
      fetch_types: false,
      prepare: false,
      idle_timeout: 5,
    });
    try {
      const r = await sql<{ label: string; secret: string }[]>`
        SELECT label, secret FROM wulf_canary
      `;
      rows = r.map((x) => ({ label: x.label, secret: x.secret }));
      canaryExfiltrated = rows.some(
        (x) => typeof x.secret === "string" && x.secret.includes("flag{w-cap-01"),
      );
    } finally {
      await sql.end({ timeout: 5 });
    }
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return base({
    test_id: "W-CAP-01",
    track: "worker",
    description:
      "Hyperdrive capability binding — read DB credentials from the binding and exfil canary rows from the backing Postgres",
    target: "env.HYPERDRIVE",
    result: canaryExfiltrated ? "accessible" : error ? "error" : "partial",
    severity: canaryExfiltrated ? "critical" : "high",
    run_id: runId,
    tags: ["misconfig", "misconfig:binding"],
    details: {
      binding_exposed: exposed,
      canary_exfiltrated: canaryExfiltrated,
      rows,
      error,
      note: "A Hyperdrive binding is full DB credentials reachable from any code that runs in the Worker — the RDS-creds-in-the-env analog. Generated/injected code (Track 4) with this binding can read the database directly.",
    },
    comparison: {
      aws_lambda:
        "accessible — equivalent to an RDS connection string / IAM DB credentials in the function environment",
      azure_functions: "accessible — DB connection string in app settings",
      gcp_functions: "accessible — Cloud SQL creds / connector in the function env",
    },
  });
};
