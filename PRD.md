# Cloudflare Prey — Product Requirements Document

> **Status:** Draft v0.1
> **Author:** Jared Gore
> **Context:** ISE 5901 — Advanced Technical Research & Communication Practicum (SANS.edu MSISE)
> **Last Updated:** 2026-05-21

---

## 1. Problem Statement

Serverless Prey (Evans & Johnson, Puma Security / SANS Institute) systematically documented the runtime environments, secret storage locations, data exfiltration paths, and monitoring gaps of AWS Lambda, Azure Functions, and Google Cloud Functions by deploying introspection functions that establish reverse shells into container-based FaaS runtimes.

Cloudflare Workers — along with the newer Dynamic Workers and SQLite-backed Durable Objects — represent a fundamentally different serverless execution model built on V8 isolates rather than containers. No equivalent introspection research exists for this platform. As Cloudflare aggressively markets Dynamic Workers for executing untrusted AI-agent-generated code, the security community lacks empirical data on what a compromised or malicious function can actually observe, access, and exfiltrate within this architecture.

This project extends the Serverless Prey methodology to the Cloudflare Workers platform.

---

## 2. Research Questions

1. **What can an attacker who achieves code execution inside a Cloudflare Worker observe about the runtime environment, and how does the blast radius compare to container-based FaaS (Lambda, Azure Functions, GCP Cloud Functions)?**
2. **Can untrusted code running inside a Dynamic Worker escape its granted capabilities — binding scope, network restrictions, or the RPC security boundary?**
3. **What is the practical attack surface of SQLite-backed Durable Objects, and what does SQL injection blast radius look like in an environment where each object owns a private, co-located database?**

---

## 3. Scope & Test Tracks

The project is organized into three test tracks, each producing a dedicated introspection module and a structured findings report.

### Track 1 — Workers Runtime Introspection (`prey-worker`)

**Goal:** Systematically enumerate what is visible from inside a standard Cloudflare Worker, mirroring the Serverless Prey documentation structure (environment, secrets, filesystem, network, monitoring).

#### 1.1 Global Scope & API Surface Enumeration

| Test ID | Description | Method |
|---------|-------------|--------|
| W-ENV-01 | Enumerate all global objects and constructors available in the V8 isolate | Recursive `Object.getOwnPropertyNames(globalThis)` walk |
| W-ENV-02 | Identify environment variables and secrets accessible via `env` bindings | Iterate and typeof-check all `env` properties |
| W-ENV-03 | Detect Cloudflare-injected globals (e.g., `caches`, `crypto`, `navigator`, `performance`) | Probe known and undocumented globals |
| W-ENV-04 | Determine V8 version and runtime feature flags | `navigator.userAgent` (if present), feature detection probes |
| W-ENV-05 | Enumerate available Web APIs vs. browser-standard APIs that are missing or restricted | Systematic feature-detection matrix |

#### 1.2 Network Reachability

| Test ID | Description | Method |
|---------|-------------|--------|
| W-NET-01 | Test outbound `fetch()` to external hosts | HTTP/HTTPS to controlled callback server |
| W-NET-02 | Probe cloud metadata endpoints (169.254.169.254, Azure IMDS, GCP metadata) | `fetch()` to known metadata IPs/hostnames |
| W-NET-03 | Test DNS resolution capabilities | `fetch()` with DNS rebinding payloads, custom hostnames |
| W-NET-04 | Attempt WebSocket connections from within a Worker | `new WebSocket()` to controlled endpoint |
| W-NET-05 | Test reachability of internal Cloudflare services | Probe known internal hostnames/IPs from blog posts and docs |
| W-NET-06 | Measure timing precision available (`performance.now()`, `Date.now()`) | Timing loop granularity measurement |

#### 1.3 Binding & Resource Discovery

| Test ID | Description | Method |
|---------|-------------|--------|
| W-BND-01 | Enumerate all declared bindings on `env` (KV, R2, D1, DO, Queues, Service Bindings) | Reflection + typeof + prototype chain inspection |
| W-BND-02 | Attempt to discover or access undeclared bindings | Probe `env` for common binding names; attempt direct construction |
| W-BND-03 | Inspect Service Binding stubs for information leakage | Enumerate methods/properties on RPC stubs |
| W-BND-04 | Attempt cross-account or cross-namespace resource access | Construct binding references with guessed IDs |

#### 1.4 Isolation & Side-Channel Observations

| Test ID | Description | Method |
|---------|-------------|--------|
| W-ISO-01 | Measure memory allocation patterns and limits | Allocate progressively, observe OOM behavior |
| W-ISO-02 | Attempt to observe co-tenant activity via timing | Repeated timing measurements under load vs. idle |
| W-ISO-03 | Test for SharedArrayBuffer / high-resolution timer availability | Direct construction attempts |
| W-ISO-04 | Probe CPU time limits and what happens at eviction boundary | Long-running computation, observe termination behavior |
| W-ISO-05 | Measure timer resolution — does the clock advance / expose sub-ms precision during pure compute? | Tight-loop sampling of `Date.now()` / `performance.now()`; three-state verdict (clamped / coarse / sub-ms). **Production-only verdict — local `wrangler dev` uses the host OS clock.** |
| W-ISO-06 | Counter-based clock amplification — can a busy-loop timer be calibrated despite clamped clocks? | Spin a counter until the real clock ticks within one synchronous turn; report spins-per-ms or "no calibration possible". **Production-only verdict.** |

#### 1.5 Monitoring & Detection Surface

Worker-side monitoring probes are a known gap. The currently implemented monitoring probes are the Durable Object `DO-MON-01` / `DO-MON-02` / `DO-MON-03` series; do not cite phantom `W-MON-*` IDs as validation until a Worker observability probe family is actually added.

---

### Track 2 — Dynamic Workers Sandbox Escape Testing (`prey-dynamic`)

**Goal:** Probe the security boundary between a parent Worker and a dynamically-loaded child Worker executing untrusted code, testing the capability-based sandbox model.

#### 2.1 Binding & Capability Escape

| Test ID | Description | Method |
|---------|-------------|--------|
| D-CAP-01 | Enumerate what the child isolate can see in its global scope vs. a standard Worker | Compare `globalThis` walk results between Track 1 and Track 2 |
| D-CAP-02 | Attempt to access bindings not explicitly passed to the Dynamic Worker | Probe `env` for KV/R2/D1/DO bindings the parent has but didn't pass |
| D-CAP-03 | Attempt to discover the parent Worker's environment variables / secrets | Prototype chain walking, `arguments.callee`, stack trace inspection |
| D-CAP-04 | Test whether RPC stubs leak information about the parent's other bindings | Inspect stub prototypes, enumerate hidden properties |
| D-CAP-05 | Attempt to call RPC methods not exposed on the declared interface | Fuzzing method names on the stub, `Reflect.ownKeys()` |

#### 2.2 Network Isolation (`globalOutbound`) Bypass

| Test ID | Description | Method |
|---------|-------------|--------|
| D-NET-01 | Verify `globalOutbound: null` blocks `fetch()` | Attempt `fetch()` to external controlled server |
| D-NET-02 | Test alternative exfiltration via DNS resolution | Encode data in DNS queries to controlled nameserver |
| D-NET-03 | Test exfiltration via RPC return values | Return large/encoded payloads through the RPC response |
| D-NET-04 | Test exfiltration via error messages and stack traces | Throw errors containing sensitive data, observe parent handling |
| D-NET-05 | Test exfiltration via timing / covert channels | Modulate response latency to encode bits |
| D-NET-06 | Attempt `WebSocket` construction inside a networkless Dynamic Worker | `new WebSocket()` with `globalOutbound: null` |
| D-NET-07 | Test `globalOutbound` with an interceptor — can the child detect or influence the interceptor? | Probe outbound handler behavior with crafted requests |

#### 2.3 RPC Bridge Integrity

| Test ID | Description | Method |
|---------|-------------|--------|
| D-RPC-01 | Send malformed / oversized payloads through RPC | Prototype pollution payloads, circular references, massive strings |
| D-RPC-02 | Test serialization/deserialization boundary for type confusion | Pass unexpected types (Proxy, Symbol, WeakRef) across RPC |
| D-RPC-03 | Attempt to obtain a reference to the parent Worker's `ctx` or `env` via RPC | Return value manipulation, getter traps |
| D-RPC-04 | Test whether private class properties (`#field`) are truly inaccessible | Reflection, `Object.getOwnPropertySymbols`, stack inspection |
| D-RPC-05 | Test Cap'n Proto RPC for stub enumeration / capability amplification | Attempt to clone, forward, or forge capability stubs |

#### 2.4 Isolation Boundary Probing

| Test ID | Description | Method |
|---------|-------------|--------|
| D-ISO-01 | Determine if child can detect its own Dynamic Worker status | Probe for distinguishing markers vs. standard Worker |
| D-ISO-02 | Test whether multiple Dynamic Workers spawned by the same parent share state | Shared variable mutation, timing correlation |
| D-ISO-03 | Measure resource limits (CPU, memory, wall time) in Dynamic Worker vs. standard | Comparative benchmarking |
| D-ISO-04 | Probe for V8 inspector / debugger protocol accessibility | Attempt `Debugger` statement, `inspector` module probes |

---

### Track 3 — Durable Objects Attack Surface (`prey-durable`)

**Goal:** Characterize the SQL injection blast radius and broader attack surface of SQLite-backed Durable Objects, with emphasis on the Dynamic Workers + Durable Objects composition.

#### 3.1 SQL Injection Fundamentals in `sql.exec`

| Test ID | Description | Method |
|---------|-------------|--------|
| DO-SQL-01 | Confirm classic SQLi via string concatenation in `sql.exec` | Deploy intentionally vulnerable DO with `${input}` patterns |
| DO-SQL-02 | Test stacked queries (multi-statement injection) | Inject `; DROP TABLE ...` and `; INSERT INTO ...` payloads |
| DO-SQL-03 | Test UNION-based injection for cross-table data extraction | `UNION SELECT` against known and discovered tables |
| DO-SQL-04 | Test blind SQL injection (boolean-based and time-based) | Conditional responses via `CASE WHEN`, `randomblob()` for timing |
| DO-SQL-05 | Test error-based injection for schema disclosure | Trigger SQLite error messages with type mismatches |
| DO-SQL-06 | Verify that parameterized `?` bindings prevent all injection vectors | Re-run DO-SQL-01 through DO-SQL-05 with bound parameters |

#### 3.2 SQLite-Specific Attack Surface

| Test ID | Description | Method |
|---------|-------------|--------|
| DO-SQ3-01 | Enumerate allowed PRAGMAs | Iterate known SQLite PRAGMAs, record allowed vs. blocked |
| DO-SQ3-02 | Attempt `ATTACH DATABASE` to access other databases or files | `ATTACH DATABASE ':memory:' AS ...`, file path probes |
| DO-SQ3-03 | Access the hidden `__cf_kv` table via SQL | `SELECT * FROM __cf_kv` after storing KV data |
| DO-SQ3-04 | Enumerate `sqlite_master` for full schema discovery | `SELECT * FROM sqlite_master` |
| DO-SQ3-05 | Test SQLite extension loading | `SELECT load_extension(...)` |
| DO-SQ3-06 | Test `writefile()` / `readfile()` SQLite functions | Attempt filesystem interaction via SQL functions |
| DO-SQ3-07 | Probe storage limits for denial-of-service potential | Fill 10GB limit, measure behavior and cost implications |
| DO-SQ3-08 | Test PITR (Point-in-Time Recovery) abuse — can an attacker trigger rollback? | Call PITR API to restore past state, assess access controls |

#### 3.3 Durable Objects + Dynamic Workers Composition

| Test ID | Description | Method |
|---------|-------------|--------|
| DO-DYN-01 | Deploy a Dynamic Worker with a DO binding; have AI-generated code write raw SQL | LLM-generated query code with no parameterization |
| DO-DYN-02 | Test whether the Dynamic Worker can access DO methods not explicitly exposed | Enumerate the DO stub's RPC surface from inside the sandbox |
| DO-DYN-03 | Test cross-object access — can a Dynamic Worker reach a different DO instance? | Attempt to construct or guess DO IDs/names from within the sandbox |
| DO-DYN-04 | Abuse DO WebSocket hibernation API from untrusted code | Connect WebSocket via DO, test hibernation state manipulation |
| DO-DYN-05 | Test alarm API abuse — can a Dynamic Worker schedule persistent alarms? | Attempt `ctx.storage.setAlarm()` through the RPC boundary |

#### 3.4 Monitoring & Detection for DO Attacks

| Test ID | Description | Method |
|---------|-------------|--------|
| DO-MON-01 | Determine what SQL activity is visible in Tail Workers | Execute injections, examine Tail Worker telemetry |
| DO-MON-02 | Test whether storage anomalies (mass writes, schema changes) trigger alerts | Rapidly create tables, insert bulk data |
| DO-MON-03 | Document available logging for DO SQL operations | Map Logpush / Analytics Engine coverage |

#### 3.5 Durable Object Addressing (IDOR) — `misconfig`

Operator-misconfiguration family (tag `misconfig:idor`). A Durable Object's identity is derived from the name passed to `idFromName(name)`; if an application names per-principal objects with a guessable scheme, the name is the only access control. Distinct from `DO-DYN-03` (sandbox-origin cross-object reach) and `P-TEN-04` (cross-tenant reach): this family isolates single-namespace **name guessability** and its mitigations. Uses a parameterized per-instance store route (`idor-put`/`idor-get`) on `PreyDurableObject` so the variable under test is the *name*, not query safety.

| Test ID | Description | Method | Expected |
|---------|-------------|--------|----------|
| DO-IDOR-01 | Guessable `idFromName("account-N")` lets an attacker enumerate and read other accounts' private objects | Seed canaries into sequential-named DOs; enumerate the range with no prior handle | `accessible` / `high` |
| DO-IDOR-02 | Control: a `newUniqueId()` object is unreachable by guessing names | Store in an opaque-id DO; attempt to reach it via `idFromName()` guesses | `blocked` / `informational` (secure baseline) |
| DO-IDOR-03 | Nuance: `idFromName()` is deterministic/offline-precomputable, so safety is purely a function of name entropy | Confirm determinism; show a 128-bit-random name resists the DO-IDOR-01 enumeration | `informational` / `medium` |

---

## 4. Architecture & Infrastructure

### 4.1 Overview

```
┌─────────────────────────────────────────────────────┐
│                    GitHub Repository                 │
│                  (cloudflare-prey)                   │
├─────────────────────────────────────────────────────┤
│  /infra          Terraform (CF provider) for all    │
│                  Workers, DOs, KV, R2, D1, Queues   │
│  /prey-worker    Track 1 introspection Worker       │
│  /prey-dynamic   Track 2 parent + child Workers     │
│  /prey-durable   Track 3 vulnerable DO + test suite │
│  /callback       Callback server (external VPS)     │
│  /harness        Test runner / orchestrator CLI      │
│  /results        Structured JSON findings output     │
│  /docs           Research notes, findings reports    │
└─────────────────────────────────────────────────────┘
```

### 4.2 Cloudflare Resources (Terraform-Managed)

All Cloudflare infrastructure is declared via the `cloudflare` Terraform provider for full reproducibility. Every test run should be deployable from zero with `terraform apply`.

| Resource | Purpose | Track |
|----------|---------|-------|
| Worker: `prey-worker` | Runtime introspection module | 1 |
| Worker: `prey-dynamic-parent` | Parent Worker that spawns Dynamic Workers | 2 |
| Worker Loader binding | Dynamic Worker sandbox | 2 |
| Durable Object class: `PreyDurableObject` (SQLite-backed) | Intentionally vulnerable DO for SQL testing | 3 |
| Durable Object class: `PreyDurableObjectSecure` (SQLite-backed) | Properly parameterized DO as control | 3 |
| KV Namespace: `prey-kv` | Test binding for discovery/exfiltration probes | 1, 2 |
| R2 Bucket: `prey-r2` | Test binding for discovery/exfiltration probes | 1, 2 |
| D1 Database: `prey-d1` | Test binding for discovery/exfiltration probes | 1, 2 |
| Queue: `prey-queue` | Test binding for discovery probes | 1, 2 |
| Tail Worker: `prey-tail` | Monitoring/detection surface mapping | 1, 2, 3 |
| Logpush Job | Capture request logs for IR analysis | 1, 2, 3 |
| Workers Analytics Engine | Capture custom analytics for anomaly detection | 1, 2, 3 |

### 4.3 External Callback Infrastructure

A controlled external server is needed to verify network reachability, capture exfiltration attempts, and serve as a DNS authority for rebinding tests.

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| HTTP(S) callback listener | Receive `fetch()` probes, log headers/body/timing | Lightweight Go or Node server on VPS |
| DNS authoritative server | Detect DNS-based exfiltration, rebinding tests | CoreDNS or custom listener on VPS |
| WebSocket echo server | Test WS connectivity from Workers | Simple WS server on same VPS |
| Netcat-style TCP listener | Verify raw socket (un)availability | nc / socat on VPS |

**Deployment:** Single VPS (e.g., DigitalOcean droplet) with a dedicated domain. Terraform-managed via the `digitalocean` provider or provisioned separately with Ansible.

### 4.4 Test Harness (`harness/`)

A CLI tool (Go or TypeScript) that orchestrates test execution and collects results.

**Responsibilities:**

- Invoke each test by HTTP request to the deployed Workers
- Pass test IDs and parameters as query params or JSON body
- Collect structured JSON responses from each probe
- Aggregate results into a unified findings report
- Compare results across runs for regression / change detection
- Output both machine-readable JSON and human-readable Markdown

**Invocation pattern:**

```bash
# Run all Track 1 tests
./harness run --track worker --output results/track1.json

# Run a specific test
./harness run --test W-NET-02 --output results/w-net-02.json

# Run all tracks, generate full report
./harness run --all --output results/full-report.json --format markdown
```

### 4.5 CI/CD Pipeline

GitHub Actions workflow for automated, repeatable runs:

```yaml
# .github/workflows/prey-run.yaml
# Triggers: manual dispatch, weekly schedule, push to main
#
# Jobs:
#   1. terraform-deploy  — apply infra (idempotent)
#   2. run-track-1       — execute prey-worker tests
#   3. run-track-2       — execute prey-dynamic tests
#   4. run-track-3       — execute prey-durable tests
#   5. collect-results   — aggregate JSON, generate report
#   6. terraform-destroy — tear down (optional, for cost control)
```

**Secrets management:** Cloudflare API token and Account ID stored as GitHub Actions secrets. Callback server credentials similarly stored. No secrets hardcoded in Terraform state — use `sensitive = true` outputs and remote state encryption.

---

## 5. Output Artifacts

### 5.1 Per-Test Structured Findings

Each test produces a JSON object conforming to a shared schema:

```json
{
  "test_id": "W-NET-02",
  "track": "worker",
  "timestamp": "2026-XX-XXTXX:XX:XXZ",
  "description": "Cloud metadata endpoint reachability",
  "target": "169.254.169.254",
  "result": "blocked",
  "details": {
    "http_status": null,
    "error": "fetch failed: Connection refused",
    "response_body": null
  },
  "severity": "informational",
  "comparison": {
    "aws_lambda": "accessible (IMDSv1 default)",
    "azure_functions": "accessible",
    "gcp_functions": "accessible"
  }
}
```

### 5.2 Aggregated Findings Report

A Markdown report auto-generated by the harness, organized by track and severity, suitable for inclusion in the ISE 5901 paper with minimal editing.

### 5.3 Comparison Matrix

A structured comparison between Cloudflare Workers findings and published Serverless Prey results for AWS Lambda, Azure Functions, and GCP Cloud Functions. Dimensions:

| Dimension | Lambda | Azure Functions | GCP Functions | CF Workers | CF Dynamic Workers |
|-----------|--------|-----------------|---------------|------------|--------------------|
| Execution model | Container | Container | Container | V8 isolate | V8 isolate (sandboxed) |
| Reverse shell | ✅ TCP | ✅ TCP | ✅ TCP | ❌ No raw sockets | ❌ No raw sockets |
| Metadata service | ✅ IMDS | ✅ IMDS | ✅ Metadata | ? | ? |
| Filesystem access | ✅ /tmp, /var | ✅ limited | ✅ /tmp | ? | ? |
| Secret discovery | env vars, IAM | env vars, MSI | env vars, SA | ? | ? |
| SQL injection surface | N/A (external DB) | N/A (external DB) | N/A (external DB) | N/A | DO SQLite |

(`?` = to be determined by this research)

### 5.4 Deliverables Summary

| Artifact | Format | Audience |
|----------|--------|----------|
| ISE 5901 research paper | PDF (≤30 pages) | SANS.edu advisor, Reading Room |
| ISE 5901 webinar presentation | Slides + recorded talk (30 min) | SANS community |
| `cloudflare-prey` GitHub repo | Public repository | Security community |
| Blog post(s) on jaredgore.com | MDX | Public |

---

## 6. Ethical Considerations & Responsible Disclosure

- All testing is performed against **self-owned Cloudflare accounts and resources only**.
- No testing against other tenants, shared infrastructure, or production Cloudflare services.
- If any finding reveals a vulnerability in the Cloudflare platform itself (e.g., isolate escape, binding leakage across accounts), it will be reported to Cloudflare's security team via their responsible disclosure program **before** publication.
- The published tool is designed for **self-assessment** — it introspects the caller's own environment and does not enable attacks against third parties.
- Intentionally vulnerable Durable Objects (Track 3) are deployed to the researcher's own account and destroyed after testing.

---

## 7. Success Criteria

1. **Complete test coverage** — Every test ID in Sections 3.1–3.3 has a recorded result (pass, fail, blocked, N/A) with supporting evidence.
2. **Reproducibility** — A reviewer can `terraform apply` and `./harness run --all` to independently verify findings.
3. **Comparison framework populated** — The Serverless Prey comparison matrix (Section 5.3) is filled in with empirical data for all Cloudflare columns.
4. **Actionable recommendations** — Each finding maps to a concrete defensive recommendation for Cloudflare Workers developers.
5. **Responsible disclosure complete** — Any platform-level vulnerabilities reported to Cloudflare before paper submission.

---

## 8. Timeline (Notional)

| Phase | Duration | Activities |
|-------|----------|------------|
| Infrastructure setup | 2 weeks | Terraform modules, callback server, CI pipeline, harness skeleton |
| Track 1 execution | 2 weeks | Workers introspection module development and testing |
| Track 2 execution | 3 weeks | Dynamic Workers sandbox probing (most novel, most unknown) |
| Track 3 execution | 2 weeks | Durable Objects SQL testing and DO+Dynamic composition |
| Analysis & comparison | 1 week | Aggregate results, build comparison matrix, identify themes |
| Paper drafting | 3 weeks | ISE 5901 paper writing, advisor review cycles |
| Presentation prep | 1 week | Webinar slides, demo recording |
| Buffer / disclosure | 2 weeks | Responsible disclosure window, revisions |

**Total: ~16 weeks** (aligns with ISE 5901's ~120-day window post-proposal approval)

---

## 9. Open Questions & Parking Lot

- [ ] **Project name** — working title "Cloudflare Prey"; workshop alternatives that establish lineage to Serverless Prey while being distinct
- [ ] **Advisor alignment** — confirm topic approval with ISE 5901 advisor; Brandon Evans or Eric Johnson as potential advisors given Serverless Prey authorship?
- [ ] **Cloudflare Workers Paid plan** — some features (DO 10GB, Dynamic Workers) require paid plan; budget ~$5/mo for Workers Paid during research window
- [ ] **Scope gating** — if Dynamic Workers or DO findings are thin, consider adding D1 (Cloudflare's standalone serverless SQL) as a fourth lightweight track
- [ ] **GIAC Gold alignment** — could this paper also count toward a GIAC Gold certification (e.g., GCLD Gold)?
- [ ] **Conference submission** — BSides, SANS Cloud Security Summit, or fwd:cloudsec as presentation venue beyond the ISE 5901 webinar
- [ ] **Cloudflare Containers / Sandboxes** — Cloudflare also recently GA'd full Linux container sandboxes; may warrant a brief comparison note but likely out of scope for this paper
