import { nameLooksSecret } from "../ast/patterns.js";
import type { Severity } from "../engine/rule.js";
import type { BindingEntry, WranglerConfig } from "./wrangler.js";

/** Canonical binding-type keys, aligned with BINDING_BLAST_RADIUS. */
export type BindingType =
  | "hyperdrive"
  | "secret"
  | "browser"
  | "mtls_certificate"
  | "send_email"
  | "vectorize"
  | "queue_producer"
  | "analytics_engine"
  | "kv_namespace"
  | "r2_bucket"
  | "d1_database"
  | "durable_object"
  | "service"
  | "ai"
  | "dispatch_namespace";

export interface BlastRadius {
  severity: Severity;
  probe: string;
  risk: string;
  category: "credential" | "ssrf" | "data" | "compute" | "lateral" | "detection";
}

/**
 * Every binding type, classified by the blast radius demonstrated in workerwulf
 * probes (PRD §10). Each entry cites the probe that demonstrated the risk — this
 * mapping is the tool's core publishable contribution. `severity` here is the
 * intrinsic blast radius; config rules may down-rank to "presence" severity.
 */
export const BINDING_BLAST_RADIUS: Record<BindingType, BlastRadius> = {
  hyperdrive: {
    severity: "critical",
    probe: "W-CAP-01",
    risk: "credential exposure + data exfil",
    category: "credential",
  },
  secret: {
    severity: "critical",
    probe: "W-CAP-02",
    risk: "plaintext secret retrieval",
    category: "credential",
  },
  browser: {
    severity: "high",
    probe: "W-CAP-05",
    risk: "SSRF with full browser context",
    category: "ssrf",
  },
  mtls_certificate: {
    severity: "high",
    probe: "W-CAP-07",
    risk: "authenticated SSRF via borrowed cert",
    category: "ssrf",
  },
  send_email: {
    severity: "high",
    probe: "W-CAP-03",
    risk: "email exfil / phishing from verified domain",
    category: "lateral",
  },
  vectorize: {
    severity: "high",
    probe: "W-CAP-04",
    risk: "RAG poisoning + metadata exfil",
    category: "data",
  },
  queue_producer: {
    severity: "medium",
    probe: "W-CAP-06",
    risk: "message injection / lateral movement",
    category: "lateral",
  },
  analytics_engine: {
    severity: "medium",
    probe: "W-CAP-08",
    risk: "detection telemetry poisoning",
    category: "detection",
  },
  kv_namespace: {
    severity: "medium",
    probe: "W-BND-01",
    risk: "data read/write / exfil / poisoning",
    category: "data",
  },
  r2_bucket: {
    severity: "medium",
    probe: "W-BND-01",
    risk: "data read/write / exfil / poisoning",
    category: "data",
  },
  d1_database: {
    severity: "medium",
    probe: "W-BND-01",
    risk: "SQL injection if string-interpolated",
    category: "data",
  },
  durable_object: {
    severity: "medium",
    probe: "DO-SQL-*",
    risk: "SQLi blast radius if vulnerable",
    category: "data",
  },
  service: {
    severity: "medium",
    probe: "W-BND-03",
    risk: "depends on target service capabilities",
    category: "lateral",
  },
  ai: {
    severity: "medium",
    probe: "AI-INJ-*",
    risk: "prompt injection / spend abuse",
    category: "compute",
  },
  dispatch_namespace: {
    severity: "high",
    probe: "D-CAP-*",
    risk: "code execution in sandbox",
    category: "compute",
  },
};

export interface DeclaredBinding {
  type: BindingType;
  /** Binding identifier as referenced from `env.<name>`. */
  name: string;
  /** Config section it came from, e.g. "hyperdrive[0]". */
  configKey: string;
}

function entryName(entry: BindingEntry): string {
  return entry.binding ?? entry.name ?? "(unnamed)";
}

/** Enumerate every declared binding in a (resolved) wrangler config. */
export function declaredBindings(config: WranglerConfig): DeclaredBinding[] {
  const out: DeclaredBinding[] = [];

  const arraySections: Array<[BindingType, BindingEntry[] | undefined]> = [
    ["hyperdrive", config.hyperdrive],
    ["secret", config.secrets_store_secrets],
    ["mtls_certificate", config.mtls_certificates],
    ["send_email", config.send_email],
    ["vectorize", config.vectorize],
    ["analytics_engine", config.analytics_engine_datasets],
    ["kv_namespace", config.kv_namespaces],
    ["r2_bucket", config.r2_buckets],
    ["d1_database", config.d1_databases],
    ["service", config.services],
    ["dispatch_namespace", config.dispatch_namespaces],
  ];
  for (const [type, entries] of arraySections) {
    (entries ?? []).forEach((entry, i) => {
      out.push({ type, name: entryName(entry), configKey: `${pluralKey(type)}[${i}]` });
    });
  }

  (config.queues?.producers ?? []).forEach((entry, i) => {
    out.push({ type: "queue_producer", name: entryName(entry), configKey: `queues.producers[${i}]` });
  });
  (config.durable_objects?.bindings ?? []).forEach((entry, i) => {
    out.push({ type: "durable_object", name: entryName(entry), configKey: `durable_objects.bindings[${i}]` });
  });

  if (config.ai?.binding) {
    out.push({ type: "ai", name: config.ai.binding, configKey: "ai" });
  }
  if (config.browser?.binding) {
    out.push({ type: "browser", name: config.browser.binding, configKey: "browser" });
  }

  return out;
}

/**
 * Binding names that should be treated as secrets for source analysis:
 * credential-category bindings (Secrets Store, Hyperdrive, mTLS), any binding
 * whose name looks secret, and `[vars]` keys that look secret.
 */
export function secretBindingNames(config: WranglerConfig): Set<string> {
  const names = new Set<string>();
  for (const b of declaredBindings(config)) {
    if (BINDING_BLAST_RADIUS[b.type].category === "credential" || nameLooksSecret(b.name)) {
      names.add(b.name);
    }
  }
  for (const key of Object.keys(config.vars ?? {})) {
    if (nameLooksSecret(key)) names.add(key);
  }
  return names;
}

/** Binding names of a given type (e.g. all hyperdrive bindings). */
export function bindingNamesOfType(config: WranglerConfig, type: BindingType): Set<string> {
  return new Set(declaredBindings(config).filter((b) => b.type === type).map((b) => b.name));
}

function pluralKey(type: BindingType): string {
  switch (type) {
    case "hyperdrive":
      return "hyperdrive";
    case "secret":
      return "secrets_store_secrets";
    case "mtls_certificate":
      return "mtls_certificates";
    case "send_email":
      return "send_email";
    case "vectorize":
      return "vectorize";
    case "analytics_engine":
      return "analytics_engine_datasets";
    case "kv_namespace":
      return "kv_namespaces";
    case "r2_bucket":
      return "r2_buckets";
    case "d1_database":
      return "d1_databases";
    case "service":
      return "services";
    case "dispatch_namespace":
      return "dispatch_namespaces";
    default:
      return type;
  }
}
