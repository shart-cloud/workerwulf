import type { Probe } from "./index.js";
import { base } from "./_helpers.js";

export const wObj02: Probe = async ({ runId }) => {
  const g = globalThis as Record<string, unknown>;
  const proc = g.process as Record<string, unknown> | undefined;

  if (!proc) {
    return base({
      test_id: "W-OBJ-02",
      track: "worker",
      description: "Deep walk of the process global (Node.js compat layer)",
      result: "informational",
      severity: "informational",
      run_id: runId,
      details: {
        present: false,
        note: "process global not found on globalThis",
      },
    });
  }

  const details: Record<string, unknown> = {
    present: true,
  };

  const ownNames = Object.getOwnPropertyNames(proc).sort();
  details.own_properties = ownNames;
  details.total_properties = ownNames.length;

  // env
  try {
    const env = proc.env;
    if (env && typeof env === "object") {
      const envKeys = Object.getOwnPropertyNames(env).sort();
      details["process.env"] = {
        keys: envKeys,
        count: envKeys.length,
        has_PATH: envKeys.includes("PATH"),
        has_NODE_ENV: envKeys.includes("NODE_ENV"),
        preview: Object.fromEntries(
          envKeys.slice(0, 20).map((k) => [k, String((env as Record<string, unknown>)[k]).slice(0, 128)]),
        ),
      };
    } else {
      details["process.env"] = { type: typeof env, value: String(env) };
    }
  } catch (err) {
    details["process.env"] = { error: err instanceof Error ? err.message : String(err) };
  }

  // versions
  try {
    const ver = proc.versions;
    if (ver && typeof ver === "object") {
      details["process.versions"] = Object.fromEntries(
        Object.getOwnPropertyNames(ver).map((k) => [k, String((ver as Record<string, unknown>)[k])]),
      );
    } else {
      details["process.versions"] = { type: typeof ver, value: String(ver) };
    }
  } catch (err) {
    details["process.versions"] = { error: err instanceof Error ? err.message : String(err) };
  }

  // arch, platform, argv
  for (const key of ["arch", "platform", "title", "release"]) {
    try {
      details[`process.${key}`] = String(proc[key] ?? "undefined");
    } catch (err) {
      details[`process.${key}`] = { error: err instanceof Error ? err.message : String(err) };
    }
  }

  // argv
  try {
    const argv = proc.argv;
    details["process.argv"] = Array.isArray(argv)
      ? { length: argv.length, values: argv.map(String) }
      : { type: typeof argv, value: String(argv) };
  } catch (err) {
    details["process.argv"] = { error: err instanceof Error ? err.message : String(err) };
  }

  // binding
  try {
    const binding = (proc as Record<string, unknown>).binding;
    details["process.binding_available"] = typeof binding === "function";
    if (typeof binding === "function") {
      try {
        const result = (binding as Function)("natives");
        details["process.binding_natives"] =
          result && typeof result === "object"
            ? Object.getOwnPropertyNames(result).slice(0, 20)
            : String(result);
      } catch {
        details["process.binding_call_blocked"] = true;
      }
    }
  } catch (err) {
    details["process.binding"] = { error: err instanceof Error ? err.message : String(err) };
  }

  // dlopen
  try {
    const dlopen = (proc as Record<string, unknown>).dlopen;
    details["process.dlopen_available"] = typeof dlopen === "function";
  } catch (err) {
    details["process.dlopen"] = { error: err instanceof Error ? err.message : String(err) };
  }

  // cwd / chdir
  for (const key of ["cwd", "chdir", "pid", "ppid", "uptime", "memoryUsage", "cpuUsage"]) {
    try {
      const v = (proc as Record<string, unknown>)[key];
      details[`process.${key}_available`] = typeof v === "function";
    } catch {
      details[`process.${key}_available`] = false;
    }
  }

  const anyRootEscalation =
    details["process.binding_available"] === true ||
    details["process.dlopen_available"] === true;

  return base({
    test_id: "W-OBJ-02",
    track: "worker",
    description: "Deep walk of the process global (Node.js compat layer)",
    result: anyRootEscalation ? "accessible" : "blocked",
    severity: anyRootEscalation ? "high" : "informational",
    run_id: runId,
    details,
    comparison: {
      aws_lambda: "process present, binding blocked, dlopen blocked",
      azure_functions: "process present, full Node.js surface",
      gcp_functions: "process present, full Node.js surface",
    },
  });
};
