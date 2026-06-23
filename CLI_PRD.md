# Workerwulf CLI — Product Requirements Document

> **Status:** Draft v0.3
> **Author:** Jared Gore
> **Context:** ISE 5901 — SANS.edu MSISE Practicum
> **Last Updated:** 2026-06-22
> **Package:** `packages/cli/` in the workerwulf monorepo (`@wulf/cli`)

---

## 1. Problem Statement

The Workerwulf research project has produced empirical security findings across five tracks of Cloudflare Workers platform testing — runtime introspection, Dynamic Worker sandbox escape, Durable Object SQLi blast radius, AI-agent prompt injection, and Workers for Platforms multi-tenant isolation. These findings identify specific patterns (binding misconfigurations, fail-open guards, excess capabilities, injection-prone code shapes) that can be detected statically in Worker source code and deployment configuration.

Today those detections exist in two disconnected places: Semgrep rules baked into a LlamaFirewall container (`wulf-rules.yml`), and an eight-family security smell corpus documented in `RULES_PRD.md`. Neither is usable outside the research harness. A developer building on Cloudflare Workers has no tool that encodes this knowledge.

The Cloudflare Workers capability model — where a Worker's bindings are its entire authority surface — creates a tractable least-privilege analysis problem that IAM-based platforms cannot offer. A Worker's `wrangler.toml` declares every binding it can reach; the source code shows which bindings it actually uses; the API shows what's deployed. The delta between declared and used is excess capability. The combination of a binding on an untrusted execution path is blast radius. Both are statically checkable.

This PRD specifies a CLI tool that turns workerwulf's research findings into a publishable, general-purpose scanner that anyone with a Cloudflare account can run against their own Workers.

---

## 2. Design Lineage

This tool follows the **three-layer model** established in the companion project [talos-hunter](https://github.com/jlgore/talos-hunter), which provides trust-boundary characterization for Talos Linux:

| Layer | talos-hunter | workerwulf CLI |
|---|---|---|
| **Demonstrate** | `probe` — offensive probes against live Talos clusters | Existing workerwulf harness (separate package, not in CLI) |
| **Document** | `HUNTER_PRD.md` — tracks, findings, coverage matrix | `PRD.md`, `RESULTS.md`, `RULES_PRD.md` (existing) |
| **Detect** | `audit` — static config posture scanner; nuclei templates; Sigma rules | **This tool** — `audit` (config + source) and `scan` (live account) |

Each detection rule maps back to the probe or finding that empirically demonstrated the weakness it catches. This back-reference is what distinguishes the tool from generic SAST: every rule is grounded in a demonstrated exploit against the researcher's own infrastructure.

---

## 3. Goals

1. **Zero-dependency scanning.** The CLI has no external tool requirements — no Semgrep, no Python, no Docker. A single `npx @wulf/cli audit .` works on any machine with Node.js. Source scanning uses oxc-parser (Rust/WASM, bundled as an npm package) for AST analysis.

2. **Publishable standalone tool.** A developer with no knowledge of the workerwulf research should be able to install the CLI, point it at their `wrangler.toml` or Cloudflare account, and get actionable findings about their Workers security posture.

3. **Encode empirical findings as detections.** Every probe result with a defensible static indicator (W-CAP-01 Hyperdrive cred exposure, W-CFG-05 `nodejs_compat` attack surface, F-002 unrestricted egress, etc.) should have a corresponding detection rule.

4. **Single-pass source analysis.** One AST parse of a Worker's source yields both the security smell scan (RULES_PRD families A–F) and the binding usage map for least-privilege analysis. No separate tool for each concern.

5. **Binding graph and least-privilege analysis.** Leverage the Cloudflare capability model — where bindings are the entire authority surface — to detect excess capabilities, high-blast-radius binding combinations, and missing egress controls.

6. **CI-friendly.** `wulf audit . --strict` exits non-zero on high/critical findings. No network access required for offline mode.

7. **Structured output.** Every finding is machine-readable JSON with probe back-references, suitable for aggregation into the research paper's appendix via `wulf report`.

## 4. Non-Goals

1. **Offensive probes.** The CLI does not ship injection payloads, callback server configurations, or exploit code. The existing harness (`packages/harness/`) remains the research runner.

2. **Runtime enforcement.** The CLI does not deploy, modify, or gate Workers. It scans and reports.

3. **General-purpose SAST.** The tool focuses on Cloudflare Workers-specific security patterns derived from workerwulf findings. It is not a replacement for eslint, oxlint, or general JavaScript security scanning.

4. **Multi-cloud.** This tool is Cloudflare-specific.

---

## 5. Architecture

### 5.1 Package Structure

```
packages/cli/
├── src/
│   ├── index.ts                    # CLI entry point
│   ├── commands/
│   │   ├── audit.ts                # offline config + source scanning
│   │   ├── scan.ts                 # live account analysis via CF API
│   │   └── report.ts              # result aggregation and formatting
│   ├── engine/
│   │   ├── rule.ts                 # Rule interface, registry, Finding type
│   │   ├── runner.ts              # Rule execution, result collection
│   │   └── output.ts             # JSON/markdown serialization, summary
│   ├── ast/
│   │   ├── parse.ts               # oxc-parser wrapper, SourceFile type
│   │   ├── walk.ts                # AST visitor dispatch + node utilities
│   │   ├── binding-map.ts         # Single-pass env.X member expression collector
│   │   └── patterns.ts            # Reusable AST predicate helpers
│   ├── rules/
│   │   ├── config/                # Config posture rules (wrangler.toml)
│   │   │   ├── compat-flags.ts
│   │   │   ├── bindings.ts
│   │   │   ├── wfp.ts
│   │   │   ├── egress.ts
│   │   │   └── routes.ts
│   │   ├── source/                # Source-level AST visitor rules
│   │   │   ├── secrets.ts         # Family A — hardcoded tokens, env logging
│   │   │   ├── injection.ts       # Family B — eval, new Function, dynamic import
│   │   │   ├── state.ts           # Family C — module-scope mutable state
│   │   │   ├── crypto.ts          # Family D — timing-unsafe comparison
│   │   │   ├── fail-open.ts       # Family E — catch blocks returning success
│   │   │   ├── resource.ts        # Family F — unbounded loops, missing limits
│   │   │   └── binding-use.ts     # Family G — dangerous binding access patterns
│   │   └── account/               # Live-account rules (CF API)
│   │       ├── least-priv.ts      # declared-vs-used binding diff
│   │       ├── drift.ts           # deployed-vs-source comparison
│   │       └── namespace.ts       # WfP namespace configuration
│   ├── parsers/
│   │   ├── wrangler.ts            # wrangler.toml/json parsing + types
│   │   └── bindings.ts            # binding type classification + blast radius
│   └── cf/
│       └── client.ts              # Cloudflare API client (thin wrapper)
├── package.json
├── tsconfig.json
└── README.md
```

### 5.2 Dependencies

| Dependency | Purpose |
|---|---|
| `commander` | CLI framework |
| `oxc-parser` | Rust/WASM JavaScript/TypeScript parser — full ESTree-compatible AST, zero native deps |
| `cloudflare` | Cloudflare API SDK (script listing, binding metadata, namespace config) |
| `smol-toml` | wrangler.toml parsing |
| `@wulf/shared` | `ProbeResult`, finding types, shared constants |

No external tool dependencies. Everything ships as npm packages.

### 5.3 Relationship to Existing Packages

```
@wulf/cli (this package)
  ├── imports @wulf/shared (types only)
  └── reads results from packages/harness/results/ (report aggregation only)

@wulf/harness (existing, unchanged)
  └── remains the offensive probe runner; not absorbed

@wulf/llamafirewall (existing)
  └── wulf-rules.yml remains the canonical Semgrep rule set for the
      LlamaFirewall container runtime scanner; the CLI rules are native
      TypeScript AST implementations of the same patterns, not a copy
```

---

## 6. Rule Engine

### 6.1 Rule Interface

Every rule implements a common interface, following the talos-hunter pattern:

```typescript
interface Rule {
  /** Unique rule ID, e.g. "WF-BIND-01" */
  id: string;
  /** Human-readable title */
  title: string;
  /** Rule severity */
  severity: Severity;
  /** Which workerwulf probe or finding empirically demonstrated this weakness */
  probe: string;
  /** Rule family from RULES_PRD.md (A–H) */
  family: string;
  /** Input surface this rule operates on */
  surface: "config" | "source" | "account";
}

interface ConfigRule extends Rule {
  surface: "config";
  check(ctx: ConfigContext): Finding[];
}

interface SourceRule extends Rule {
  surface: "source";
  check(ctx: SourceContext): Finding[];
}

interface AccountRule extends Rule {
  surface: "account";
  check(ctx: AccountContext): Finding[];
}

type Severity = "critical" | "high" | "medium" | "low" | "informational";
```

### 6.2 Finding Schema

```typescript
interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  resource: string;          // "wrangler.toml", "src/index.ts:42", "script:prey-worker"
  message: string;           // what's wrong and why
  remediation: string;       // how to fix
  probe: string;             // back-reference: "W-CAP-01", "F-002", etc.
  family: string;            // RULES_PRD family: "A" | "B" | ... | "H"
  evidence?: Evidence[];     // supporting data (config snippets, AST excerpts)
}

interface Evidence {
  type: string;              // "config" | "source" | "binding" | "api"
  label: string;
  inline?: string;           // short text payload
  file?: string;             // relative path to larger artifact
}
```

### 6.3 Rule Contexts

```typescript
/** Offline config context — parsed wrangler.toml, no network. */
interface ConfigContext {
  config: WranglerConfig;
  configPath: string;
}

/** Source analysis context — AST + binding map from a single parse pass. */
interface SourceContext {
  config: WranglerConfig;
  configPath: string;
  source: SourceFile;        // oxc-parser AST + raw text
  bindingMap: BindingMap;    // env.X references collected during parse walk
}

/** Live scan context — populated from the Cloudflare API. */
interface AccountContext {
  accountId: string;
  scripts: ScriptMetadata[];
  namespaces?: WfPNamespace[];
  bindingMap?: BindingMap;   // from downloaded bundle parse, if available
  localSource?: SourceFile;  // for drift comparison
}
```

### 6.4 Rule Registration

Rules self-register at module scope:

```typescript
// rules/config/compat-flags.ts
import { registerConfig } from "../../engine/rule.js";

registerConfig({
  id: "WF-CFG-01",
  title: "nodejs_compat exposes process.env as a second secret enumeration path",
  severity: "medium",
  probe: "W-CFG-05",
  family: "G",
  check(ctx) {
    const flags = ctx.config.compatibility_flags ?? [];
    if (!flags.includes("nodejs_compat")) return [];
    return [{
      rule_id: this.id,
      title: this.title,
      severity: this.severity,
      resource: `${ctx.configPath}:compatibility_flags`,
      message:
        "nodejs_compat injects Node.js globals (Buffer, process, global, setImmediate) " +
        "and surfaces every [vars] entry through process.env — a second config/secret " +
        "enumeration path that does not exist without the flag. W-CFG-05 confirmed 5 " +
        "globals + 3 vars via process.env with the flag on vs zero surface with it off.",
      remediation:
        "Remove nodejs_compat if not required. If required, audit all [vars] entries " +
        "as if they were environment variables readable by any code path in the Worker.",
      probe: this.probe,
      family: this.family,
    }];
  },
});
```

---

## 7. AST Source Engine

### 7.1 Design Principle: Single Parse, Multiple Concerns

A Worker's source file is parsed once by oxc-parser. The resulting AST is walked once. During that walk, two things happen simultaneously:

1. **Binding map construction.** Every `MemberExpression` accessing a property on the `env` parameter (the fetch handler's second arg) is recorded: `env.MY_KV` → `{ name: "MY_KV", node, loc }`. This produces the `BindingMap` used by least-privilege analysis and binding-use rules.

2. **Pattern matching.** Source rules register visitor callbacks for specific AST node types. The walker dispatches to all registered visitors for each node. A rule checking for `eval` calls registers a `CallExpression` visitor; a rule checking for module-scope mutable state registers a `VariableDeclaration` visitor with a scope-depth predicate.

Adding a rule never adds a parse pass — it's one more callback on the existing walk.

### 7.2 oxc-parser Integration

```typescript
// ast/parse.ts
import { parseSync } from "oxc-parser";

interface SourceFile {
  path: string;
  text: string;
  ast: Program;          // ESTree-compatible AST from oxc-parser
  comments: Comment[];
}

function parse(path: string, text: string): SourceFile {
  const result = parseSync(path, text, {
    sourceType: "module",
    sourceFilename: path,
  });
  if (result.errors.length > 0) {
    // Non-fatal: log parse errors, return partial AST.
    // Workers source is sometimes unconventional (Wasm imports, etc.)
  }
  return { path, text, ast: result.program, comments: result.comments };
}
```

### 7.3 AST Visitor Pattern

```typescript
// ast/walk.ts
type NodeType = string;  // ESTree node type, e.g. "CallExpression"

interface Visitor {
  nodeType: NodeType | NodeType[];
  /** Return true to skip descending into children. */
  enter(node: Node, ancestors: Node[]): boolean | void;
}

/**
 * Walk the AST depth-first, dispatching to registered visitors by node type.
 * Ancestors array gives parent chain for scope-depth and context checks.
 */
function walk(ast: Program, visitors: Visitor[]): void;
```

### 7.4 Binding Map

```typescript
// ast/binding-map.ts
interface BindingRef {
  name: string;              // binding name, e.g. "MY_KV"
  accessType: "dot" | "bracket" | "destructure";
  loc: SourceLocation;
  ancestors: string[];       // ancestor node types for context
  methodCall?: string;       // if env.X.get(), captures "get"
}

interface BindingMap {
  /** All env.X references found in source. */
  refs: BindingRef[];
  /** Deduplicated set of binding names referenced. */
  used: Set<string>;
  /** Whether the env parameter was destructured (complicates analysis). */
  envDestructured: boolean;
}
```

The binding map visitor registers on `MemberExpression` and `ObjectPattern` (for destructuring). It identifies the `env` parameter by walking up to the nearest `FunctionDeclaration`/`ArrowFunctionExpression`/`MethodDefinition` matching the Workers fetch handler signature: `(request, env, ctx)` or `{ fetch(request, env, ctx) }` or `export default { fetch(req, env, ctx) {} }`.

### 7.5 AST Predicate Helpers

Reusable predicates that source rules compose:

```typescript
// ast/patterns.ts

/** True if node is a call to a named function (eval, setTimeout, etc.) */
function isCallTo(node: CallExpression, name: string): boolean;

/** True if node is `new X(...)` for a given constructor name */
function isConstructOf(node: NewExpression, name: string): boolean;

/** True if the node is at module scope (no enclosing function/class) */
function isModuleScope(ancestors: Node[]): boolean;

/** True if this node is inside a CatchClause body */
function isInCatchBlock(ancestors: Node[]): boolean;

/** True if node is a string literal matching a token/secret pattern */
function looksLikeSecret(node: StringLiteral): boolean;

/** True if node is a binary comparison (===, ==, !==, !=)
 *  where one operand looks like a secret/token identifier */
function isTimingUnsafeComparison(node: BinaryExpression): boolean;

/** True if node is a `new Response(...)` or object literal with
 *  success-shaped properties (status 200, decision "allow", safe true) */
function isSuccessValue(node: Node): boolean;

/** True if node is inside a loop body (for, while, do, for-of, for-in) */
function isInLoop(ancestors: Node[]): boolean;

/** Extract string value from a node if it's a string literal or template
 *  with no expressions */
function staticStringValue(node: Node): string | undefined;
```

---

## 8. Source Rules — RULES_PRD Family Mapping

Each RULES_PRD family becomes a source rule module with one or more AST visitors. Rules share the predicate helpers from §7.5 and are native TypeScript implementations of the same patterns as the Semgrep rules in `wulf-rules.yml`.

### Family A — Secrets & Credentials (`rules/source/secrets.ts`)

| Rule ID | Visitor | What it catches |
|---|---|---|
| WF-SEC-01 | `StringLiteral` | String literal matching token/key patterns (high-entropy hex, `sk_live_*`, `wrangler_*`, etc.) |
| WF-SEC-02 | `CallExpression` | `console.log` / `console.error` whose arguments include `env.X` member expressions for secret-classified bindings |
| WF-SEC-03 | `ReturnStatement`, `NewExpression` | env binding value passed into a `new Response()` body or returned from fetch handler without redaction |

### Family B — Injection & Dynamic Code (`rules/source/injection.ts`)

| Rule ID | Visitor | What it catches |
|---|---|---|
| WF-INJ-01 | `CallExpression` | Direct `eval()` call |
| WF-INJ-02 | `NewExpression` | `new Function()` construction |
| WF-INJ-03 | `CallExpression` | `setTimeout` / `setInterval` with a string first argument |
| WF-INJ-04 | `ImportExpression` | Dynamic `import()` with a non-literal argument |

### Family C — Cross-Request State (`rules/source/state.ts`)

| Rule ID | Visitor | What it catches |
|---|---|---|
| WF-STATE-01 | `VariableDeclaration` | `let` or `var` at module scope (outside any function/class/block) with a mutable initializer |
| WF-STATE-02 | `VariableDeclaration` | `const` at module scope initialized to `new Map()`, `new Set()`, `[]`, or `{}` — const reference but mutable contents |

### Family D — Crypto & Comparison (`rules/source/crypto.ts`)

| Rule ID | Visitor | What it catches |
|---|---|---|
| WF-CRYPTO-01 | `BinaryExpression` | `===` / `==` / `!==` / `!=` where one operand is an identifier or member expression whose name contains `secret`, `token`, `key`, `password`, `api_key`, or matches a declared secret binding name, and the comparison is not wrapped in `crypto.subtle.timingSafeEqual` |
| WF-CRYPTO-02 | `CallExpression` | `Math.random()` used in a security-relevant context (token generation, nonce, ID) |

### Family E — Boundary & Fail-Open (`rules/source/fail-open.ts`)

| Rule ID | Visitor | What it catches |
|---|---|---|
| WF-FAIL-01 | `CatchClause` | Catch block whose body contains a return statement producing a success-shaped value: `new Response("ok")`, `{ decision: "allow" }`, `{ safe: true }`, `{ blocked: false }`, status 200. Static twin of F-001 (guard gate fails open). |
| WF-FAIL-02 | `CatchClause` | Empty catch block (`catch (e) {}`) — silent error swallowing |
| WF-FAIL-03 | `TryStatement` | Try block wrapping a guard/scanner call where the catch does not re-throw or return an error/block verdict |

### Family F — Concurrency & Resource (`rules/source/resource.ts`)

| Rule ID | Visitor | What it catches |
|---|---|---|
| WF-RES-01 | `CallExpression` | `fetch()` call inside a loop body with no visible iteration bound or `AbortSignal` timeout |
| WF-RES-02 | `CallExpression` | `sql.exec()` or `prepare().bind().run()` where the SQL argument contains template literal expressions (string interpolation — DO-SQL-01 static twin) |

### Family G — Binding Access Patterns (`rules/source/binding-use.ts`)

These rules use the binding map (§7.4) and the blast-radius classification (§10) together:

| Rule ID | Visitor | What it catches |
|---|---|---|
| WF-BUSE-01 | `MemberExpression` | `env.HYPERDRIVE.connectionString` accessed and passed to a response, fetch body, or logged — credential exposure path (W-CAP-01 static twin) |
| WF-BUSE-02 | `CallExpression` | `env.BROWSER` passed to `puppeteer.launch()` where the navigated URL comes from request input — SSRF-with-browser (W-CAP-05 static twin) |
| WF-BUSE-03 | `CallExpression` | `env.X.fetch()` where X is a service binding and the URL argument is constructed from user input — SSRF via service binding |
| WF-BUSE-04 | `CallExpression` | `sql.exec()` called with string concatenation/interpolation rather than parameterized `?` bindings (DO-SQL-01 through DO-SQL-05 static twin) |

---

## 9. Config Posture Rules

Parsed from wrangler.toml. No source analysis required.

### 9.1 Compatibility & Configuration

| Rule ID | Severity | Probe | What it detects |
|---|---|---|---|
| WF-CFG-01 | medium | W-CFG-05 | `nodejs_compat` in compatibility_flags |
| WF-CFG-02 | informational | W-ENV-03 | Missing `compatibility_date` or stale (>6 months old) |

### 9.2 Binding Blast Radius

These flag the *presence* of high-blast-radius bindings. The finding explains the demonstrated risk; remediation recommends access controls proportional to the blast radius.

| Rule ID | Severity | Probe | What it detects |
|---|---|---|---|
| WF-BIND-01 | high | W-CAP-01 | Hyperdrive binding — credential exposure + data exfil |
| WF-BIND-02 | high | W-CAP-02 | Secrets Store binding — plaintext secret retrieval |
| WF-BIND-03 | medium | W-CAP-06 | Queue producer binding — lateral-movement injection surface |
| WF-BIND-04 | high | W-CAP-05 | Browser Rendering binding — SSRF-with-a-browser |
| WF-BIND-05 | high | W-CAP-07 | mTLS certificate binding — authenticated SSRF via borrowed cert |
| WF-BIND-06 | medium | W-CAP-08 | Analytics Engine binding — detection-integrity poisoning |
| WF-BIND-07 | medium | W-CAP-04 | Vectorize binding — RAG poisoning + metadata exfil |
| WF-BIND-08 | high | W-CAP-03 | send_email binding — email exfil/phishing channel |

### 9.3 Egress & Network Controls

| Rule ID | Severity | Probe | What it detects |
|---|---|---|---|
| WF-EGR-01 | high | F-002 | No outbound worker configured on a WfP dispatch namespace |
| WF-EGR-02 | medium | D-NET-01 | Dynamic Worker loader without `globalOutbound: null` |

### 9.4 Workers for Platforms Namespace

| Rule ID | Severity | Probe | What it detects |
|---|---|---|---|
| WF-WFP-01 | high | P-TEN-* | WfP namespace with `trusted_workers = true` |
| WF-WFP-02 | medium | P-LIM-* | WfP dispatch without custom limits (`cpuMs`, `subRequests`) |

---

## 10. Binding Blast-Radius Classification

Every Cloudflare binding type is classified by the blast radius demonstrated in workerwulf probes. This table drives both the config rules (§9.2) and the least-privilege analysis (§12).

```typescript
interface BlastRadius {
  severity: Severity;
  probe: string;
  risk: string;
  category: "credential" | "ssrf" | "data" | "compute" | "lateral" | "detection";
}

const BINDING_BLAST_RADIUS: Record<string, BlastRadius> = {
  hyperdrive:        { severity: "critical", probe: "W-CAP-01",  risk: "credential exposure + data exfil",
                       category: "credential" },
  secret:            { severity: "critical", probe: "W-CAP-02",  risk: "plaintext secret retrieval",
                       category: "credential" },
  browser:           { severity: "high",     probe: "W-CAP-05",  risk: "SSRF with full browser context",
                       category: "ssrf" },
  mtls_certificate:  { severity: "high",     probe: "W-CAP-07",  risk: "authenticated SSRF via borrowed cert",
                       category: "ssrf" },
  send_email:        { severity: "high",     probe: "W-CAP-03",  risk: "email exfil / phishing from verified domain",
                       category: "lateral" },
  vectorize:         { severity: "high",     probe: "W-CAP-04",  risk: "RAG poisoning + metadata exfil",
                       category: "data" },
  queue_producer:    { severity: "medium",   probe: "W-CAP-06",  risk: "message injection / lateral movement",
                       category: "lateral" },
  analytics_engine:  { severity: "medium",   probe: "W-CAP-08",  risk: "detection telemetry poisoning",
                       category: "detection" },
  kv_namespace:      { severity: "medium",   probe: "W-BND-01",  risk: "data read/write / exfil / poisoning",
                       category: "data" },
  r2_bucket:         { severity: "medium",   probe: "W-BND-01",  risk: "data read/write / exfil / poisoning",
                       category: "data" },
  d1_database:       { severity: "medium",   probe: "W-BND-01",  risk: "SQL injection if string-interpolated",
                       category: "data" },
  durable_object:    { severity: "medium",   probe: "DO-SQL-*",  risk: "SQLi blast radius if vulnerable",
                       category: "data" },
  service:           { severity: "variable", probe: "W-BND-03",  risk: "depends on target service capabilities",
                       category: "lateral" },
  ai:                { severity: "medium",   probe: "AI-INJ-*",  risk: "prompt injection / spend abuse",
                       category: "compute" },
  dispatch_namespace:{ severity: "high",     probe: "D-CAP-*",   risk: "code execution in sandbox",
                       category: "compute" },
};
```

Each entry cites the probe that demonstrated the risk empirically. This is the tool's core publishable contribution.

---

## 11. Commands

### 11.1 `wulf audit` — Offline Config & Source Scanning

```
wulf audit [paths...] [options]

Arguments:
  paths              wrangler.toml files, source directories, or directories
                     containing wrangler.toml (default: current directory)

Options:
  --source           also scan Worker source files via oxc-parser AST analysis
  --strict           exit 1 on any high/critical finding
  --json             output findings as JSON (default: human-readable table)
  --severity <level> minimum severity to report (default: "low")
  --ignore <ids>     comma-separated rule IDs to suppress
```

**Behavior:**

1. Locate `wrangler.toml` files in the given paths. For each:
   a. Parse the config, resolve `[env.*]` overrides.
   b. Run all config posture rules (§9).
   c. If `--source` is set and the config declares a `main` entry point:
      - Resolve the source file path.
      - Parse with oxc-parser.
      - Build the binding map (single walk).
      - Run all source rules (§8) against the AST + binding map.
2. Aggregate findings, sort by severity, output.

**Directory auto-discovery:** If a path is a directory, the CLI walks it looking for `wrangler.toml` / `wrangler.json` / `wrangler.jsonc` files (skipping `node_modules`). Each discovered config is scanned independently.

### 11.2 `wulf scan` — Live Account Analysis

```
wulf scan [options]

Options:
  --account-id <id>  Cloudflare account ID (or CLOUDFLARE_ACCOUNT_ID env)
  --api-token <tok>  Cloudflare API token (or CLOUDFLARE_API_TOKEN env)
  --source <dir>     local source root for drift detection
  --namespace <name> restrict to a specific WfP dispatch namespace
  --json             output findings as JSON
  --strict           exit 1 on any high/critical finding
```

**What it checks:**

| Rule ID | Severity | Probe | What it detects |
|---|---|---|---|
| WF-PRIV-01 | medium | W-BND-01 | Declared binding not referenced in deployed script source |
| WF-PRIV-02 | high | W-CAP-* | High-blast-radius binding on a script with a public route |
| WF-DRIFT-01 | medium | — | Deployed script content diverges from local source |
| WF-NS-01 | high | P-TEN-* | WfP namespace in trusted mode |
| WF-NS-02 | high | F-002 | WfP namespace without an outbound worker |
| WF-NS-03 | medium | P-LIM-* | WfP dispatch worker without custom limits |
| WF-NS-04 | medium | P-DISP-* | WfP namespace with scripts not in untrusted mode |

**Cloudflare API surface used:**

| Endpoint | Purpose |
|---|---|
| `GET /accounts/:id/workers/scripts` | List deployed scripts |
| `GET /accounts/:id/workers/scripts/:name` | Script metadata + binding declarations |
| `GET /accounts/:id/workers/scripts/:name/content` | Download deployed bundle for AST analysis |
| `GET /accounts/:id/workers/dispatch/namespaces` | List WfP dispatch namespaces |
| `GET /accounts/:id/workers/dispatch/namespaces/:name` | Namespace config |
| `GET /accounts/:id/workers/scripts/:name/routes` | Route bindings |

### 11.3 `wulf report` — Result Aggregation

```
wulf report [options]

Options:
  --results-dir <dir>  directory containing run result JSON files (default: ./results)
  --run-id <id>        restrict to a single run
  --format <fmt>       markdown | json (default: markdown)
  --output <path>      write to file (default: stdout)
  --matrix             render the rule × probe coverage matrix
  --include-probes     also aggregate harness probe results from a given path
```

**Coverage matrix** (`--matrix`):

```
| Probe    | Finding       | Detection Rule | Status  |
|----------|---------------|----------------|---------|
| W-CAP-01 | cred exposure | WF-BIND-01     | covered |
| W-CAP-02 | secret leak   | WF-BIND-02     | covered |
| W-CFG-05 | process.env   | WF-CFG-01      | covered |
| F-001    | fail-open     | WF-FAIL-01     | covered |
| F-002    | egress        | WF-EGR-01      | covered |
| replay-09| indirect inj  | —              | gap     |
```

Gap rows are explicit and include a rationale for why no static indicator exists.

---

## 12. Least-Privilege Binding Analysis (`wulf scan`)

For each deployed script:

1. **Fetch binding declarations** from the script metadata API — the complete capability set.

2. **Download the deployed bundle** and parse with oxc-parser. Build the binding map (§7.4) — the same single-pass walk used by source rules.

3. **Diff declared vs. referenced.** Any binding declared but absent from the binding map is flagged as excess capability. Severity inherits from the binding's blast-radius classification (§10).

4. **Flag high-risk combinations.** A script with a high-blast-radius binding (Hyperdrive, Browser, mTLS, Secrets Store) and a public route is flagged as a compound risk.

### 12.1 Limitations (Documented Honestly)

These are stated in finding output so users understand the analysis boundaries:

- **Bundled/minified code.** Binding references may be obscured by bundlers (variable renaming, property mangling). The binding map walker handles `env.X`, `env['X']`, and simple destructuring (`const { X } = env`), but cannot track bindings through arbitrary indirection. False negatives are possible.

- **Auth detection is heuristic.** The "public route + high-blast-radius binding" compound finding looks for common auth patterns (`request.headers.get("Authorization")`, JWT verification calls) but cannot verify correctness.

- **Service binding opacity.** Without analyzing the target Worker's code, the tool cannot assess what a service binding reaches. Flagged as "variable risk."

- **Downloaded bundles may differ from source.** Build transforms (tree-shaking, dead-code elimination) can remove binding references. WF-DRIFT-01 exists partly to surface this.

---

## 13. Output Format

### 13.1 Human-Readable (default)

```
config: wrangler.toml
  [high]   WF-BIND-01  binding:HYPERDRIVE
      Hyperdrive binding on publicly-routed Worker. W-CAP-01 demonstrated that a
      Hyperdrive binding exposes the backing database's host, username, and password
      to any code path that reads env.HYPERDRIVE.
      fix: restrict the Worker's route to authenticated paths; consider a service
      binding to an intermediary with query allowlisting.  (probe: W-CAP-01)

  [medium] WF-CFG-01   compat:nodejs_compat
      nodejs_compat exposes process.env as a second secret enumeration path.
      W-CFG-05 confirmed 5 Node globals + 3 vars surfaced via process.env.
      fix: remove nodejs_compat if not required; audit [vars] entries as readable
      environment variables.  (probe: W-CFG-05)

source: src/index.ts
  [high]   WF-FAIL-01  src/index.ts:90
      Catch block returns { decision: "allow" } — scanner errors will fail open.
      F-001 demonstrated this pattern allows unscanned code to reach execution
      under a "block" policy when the guard container is degraded.
      fix: return { decision: "block" } or re-throw on error paths in guard
      helpers.  (probe: F-001)

3 finding(s): 0 critical, 2 high, 1 medium, 0 low, 0 info
```

### 13.2 JSON

```json
{
  "run_id": "...",
  "timestamp": "2026-06-22T...",
  "sources": [
    {
      "source": "wrangler.toml",
      "findings": [ { "rule_id": "WF-BIND-01", "..." : "..." } ]
    },
    {
      "source": "src/index.ts",
      "findings": [ { "rule_id": "WF-FAIL-01", "..." : "..." } ]
    }
  ],
  "counts": { "critical": 0, "high": 2, "medium": 1, "low": 0, "informational": 0 }
}
```

---

## 14. Rule-to-Probe Traceability

Every rule must satisfy one of:

1. **Empirically grounded** — cites a specific workerwulf probe ID that demonstrated the weakness in a live Cloudflare environment, documented in `RESULTS.md` or track results.

2. **Corpus-derived** — cites a RULES_PRD.md family and pattern identified through systematic code review and validated against known vulnerable patterns.

Rules without either basis are not included. `wulf report --matrix` validates that every rule's `probe` field references a known probe ID. The build pipeline enforces this.

---

## 15. Implementation Phases

### Phase 1 — Config Posture Scanner + AST Engine Foundation

The minimum viable tool. Config scanning works end-to-end; the AST engine is built with initial source rules.

Deliverables:
- `packages/cli/` scaffolding (commander, tsconfig, package.json)
- wrangler.toml parser with typed config model and `[env.*]` override resolution
- Rule engine (interface, registry, runner, finding schema, JSON + table output)
- Config rules: WF-CFG-01/02, WF-BIND-01–08, WF-EGR-01/02, WF-WFP-01/02
- oxc-parser integration: parse wrapper, AST walker, binding map collector
- Initial source rules: WF-FAIL-01 (fail-open catch), WF-INJ-01/02 (eval, new Function), WF-SEC-01 (hardcoded secrets)
- `wulf audit` command with `--source`, `--json`, `--strict`

### Phase 2 — Full Source Rule Set

Complete the RULES_PRD family coverage.

Deliverables:
- Remaining source rules: families A–G complete (§8)
- AST predicate helpers (§7.5) fully implemented and tested
- Binding-use rules (WF-BUSE-*) connecting source patterns to blast-radius classification

### Phase 3 — Live Account Scanner

Add Cloudflare API integration and least-privilege analysis.

Deliverables:
- Cloudflare API client (`cloudflare` SDK wrapper)
- Script metadata fetching, bundle download, binding declaration extraction
- Least-privilege binding analysis (declared-vs-used diff)
- WfP namespace posture rules
- Drift detection (deployed-vs-local source comparison)
- `wulf scan` command

### Phase 4 — Report Aggregation

Publishable output and paper-ready artifacts.

Deliverables:
- Result persistence (per-run JSON files)
- Markdown report generator
- Rule × probe coverage matrix
- Optional harness probe result ingestion
- `wulf report` command with `--matrix`

---

## 16. Success Criteria

1. **`wulf audit .` runs in <2s on a typical Workers project** with no network access and no external tool dependencies.

2. **Every W-CAP probe has a config detection rule.** The blast-radius table (§10) is fully covered.

3. **Every RULES_PRD family (A–H) has at least one source rule.** The oxc-parser AST visitors cover the same patterns as the existing Semgrep rules without requiring Semgrep.

4. **The coverage matrix has no silent gaps.** Where a probe finding has no static indicator, the matrix explicitly says "gap" with an explanation.

5. **A developer unfamiliar with workerwulf** can `npx @wulf/cli audit .` against their own project and understand the findings.

6. **CI integration works.** `wulf audit . --strict` in GitHub Actions exits non-zero on high/critical findings and produces parseable JSON.

7. **Probe back-references are validated.** Every rule's `probe` field references a probe ID documented in the project.

---

## 17. Open Questions

- [ ] **CLI binary name.** `wulf` is short for CLI use; `workerwulf` is more discoverable for npm. Could publish as `@wulf/cli` with a `wulf` bin alias.
- [ ] **Distribution.** `npx @wulf/cli audit` vs. compiled standalone binary via `bun build --compile`? npm is simpler; binary is better for non-JS users.
- [ ] **Rule suppression.** Inline `// wulf-ignore WF-BIND-01` comments for acknowledged risks? Standard in security tooling but adds comment-association complexity. Could defer to `--ignore` flag for v1.
- [ ] **Wrangler environments.** `wrangler.toml` supports `[env.production]` overrides. A binding in `[env.production]` but not in base is still a risk. Parser must merge and scan each environment independently.
- [ ] **Monorepo support.** Many Workers projects are monorepos with multiple wrangler.toml files. Directory auto-discovery handles this, but should findings be grouped per-Worker or aggregated?
- [ ] **oxc-parser version pinning.** oxc-parser is actively developed and its AST shape could change. Pin the version and document which ESTree variant is expected.
- [ ] **Bundled source analysis.** For `wulf scan`, downloaded bundles are post-build. Should the tool detect common bundler output (esbuild, webpack) and adjust analysis, or document the limitation?
