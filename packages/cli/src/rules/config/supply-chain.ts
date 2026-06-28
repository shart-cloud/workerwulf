import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

import { highBlastBindingNames, highBlastSummary } from "../source/_utils.js";
import { registerConfig, type ConfigRule, type Finding } from "../../engine/rule.js";

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".wrangler",
  ".netlify",
  ".vercel",
  ".output",
  ".svelte-kit",
  "coverage",
  "results",
  "netlify-target",
  "test",
  "tests",
  "__tests__",
]);
const INSTALL_SCRIPTS = new Set(["preinstall", "install", "postinstall", "prepare"]);
const SECRET_NAME_RE = /(HF_TOKEN|CF_API_TOKEN|CLOUDFLARE_API_TOKEN|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|API[_-]?KEY|SECRET|PASSWORD|PRIVATE[_-]?KEY)/i;

registerConfig({
  id: "WF-SC-PKG-01",
  title: "Package install-time script in Worker package",
  severity: "medium",
  probe: "W-CAP-*",
  family: "H",
  check(ctx) {
    const pkgPath = join(dirname(resolve(ctx.configPath)), "package.json");
    if (!existsSync(pkgPath)) return [];
    const pkg = readJson(pkgPath) as { scripts?: Record<string, string> } | undefined;
    const scripts = pkg?.scripts ?? {};
    return Object.entries(scripts)
      .filter(([name]) => INSTALL_SCRIPTS.has(name))
      .map(([name, value]) => configFinding(
        this,
        rel(pkgPath),
        `package.json declares an install-time script (${name}). Install hooks execute during dependency installation and can run before review, CI, or container builds package the Worker.`,
        "Remove install-time hooks from Worker packages unless absolutely required. Prefer explicit build scripts, pin dependencies, and review any package that needs lifecycle execution.",
        [{ type: "config", label: `scripts.${name}`, inline: value }],
      ));
  },
});

registerConfig({
  id: "WF-SC-PKG-02",
  title: "Third-party runtime dependency with high-blast-radius bindings",
  severity: "high",
  probe: "W-CAP-*",
  family: "H",
  check(ctx) {
    if (highBlastBindingNames(ctx.config).size === 0) return [];
    const pkgPath = join(dirname(resolve(ctx.configPath)), "package.json");
    if (!existsSync(pkgPath)) return [];
    const pkg = readJson(pkgPath) as { dependencies?: Record<string, string> } | undefined;
    const deps = Object.entries(pkg?.dependencies ?? {}).filter(([, spec]) => isThirdPartyRuntimeSpec(spec));
    if (deps.length === 0) return [];
    return [configFinding(
      this,
      rel(pkgPath),
      `This Worker package declares high-blast-radius bindings (${highBlastSummary(ctx.config)}) and runtime third-party dependencies (${deps.map(([name]) => name).join(", ")}). Bundled dependency code executes with the full binding set at runtime.`,
      "Minimize runtime dependencies in privileged Workers, pin and review dependency code, split high-risk bindings into smaller Workers, or isolate third-party code behind a service boundary with least-privilege bindings.",
      [{ type: "config", label: "dependencies", inline: deps.map(([name, spec]) => `${name}@${spec}`).join(", ") }],
    )];
  },
});

registerConfig({
  id: "WF-SC-LOCK-01",
  title: "Package manager lockfile missing from audit scope",
  severity: "medium",
  probe: "W-CAP-*",
  family: "H",
  check(ctx) {
    const dir = dirname(resolve(ctx.configPath));
    const pkgPath = join(dir, "package.json");
    if (!existsSync(pkgPath)) return [];
    if (findUp(dir, ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lockb"])) return [];
    return [configFinding(
      this,
      rel(pkgPath),
      "A package.json was found for this Worker package, but no package-manager lockfile was found in this package or its parents. Offline supply-chain review cannot confirm the resolved dependency graph.",
      "Commit and scan the lockfile for the package manager used by the repo. Run dependency audit explicitly with --dependency-audit only when network access is intended.",
    )];
  },
});

registerConfig({
  id: "WF-SC-DOCKER-01",
  title: "Dockerfile base image is not digest-pinned",
  severity: "medium",
  probe: "W-CAP-*",
  family: "H",
  check(ctx) {
    const findings: Finding[] = [];
    for (const dockerfile of findFiles(dirname(resolve(ctx.configPath)), isDockerfile)) {
      const lines = readFileSync(dockerfile, "utf8").split(/\r?\n/);
      lines.forEach((line, index) => {
        const trimmed = line.trim();
        if (!/^FROM\s+/i.test(trimmed) || trimmed.includes("@sha256:")) return;
        findings.push(configFinding(
          this,
          `${rel(dockerfile)}:${index + 1}`,
          "Dockerfile FROM uses a tag or floating image reference instead of a digest-pinned base image. Rebuilds can silently consume different upstream content.",
          "Pin container base images by immutable digest, for example FROM image@sha256:<digest>, and update the digest through reviewable dependency maintenance.",
          [{ type: "config", label: "FROM", inline: trimmed }],
        ));
      });
    }
    return findings;
  },
});

registerConfig({
  id: "WF-SC-DOCKER-02",
  title: "Docker build uses secret-like ARG or ENV",
  severity: "high",
  probe: "W-CAP-*",
  family: "H",
  check(ctx) {
    const findings: Finding[] = [];
    for (const dockerfile of findFiles(dirname(resolve(ctx.configPath)), isDockerfile)) {
      const lines = readFileSync(dockerfile, "utf8").split(/\r?\n/);
      lines.forEach((line, index) => {
        const trimmed = line.trim();
        if (!/^(ARG|ENV)\s+/i.test(trimmed) || !SECRET_NAME_RE.test(trimmed)) return;
        findings.push(configFinding(
          this,
          `${rel(dockerfile)}:${index + 1}`,
          "Dockerfile declares a secret-like ARG or ENV during image build. Build args and environment values can leak through image history, logs, layer cache, or provenance metadata.",
          "Use BuildKit secrets or CI secret mounts for build-time credentials, avoid persisting tokens in ENV, and ensure tokens such as HF_TOKEN, CF_API_TOKEN, and NPM_TOKEN are not captured in layers.",
          [{ type: "config", label: "Docker secret", inline: trimmed.replace(/=.*/, "=<redacted>") }],
        ));
      });
    }
    return findings;
  },
});

registerConfig({
  id: "WF-SC-PY-01",
  title: "Python runtime requirement is unbounded or ranged",
  severity: "medium",
  probe: "W-CAP-*",
  family: "H",
  check(ctx) {
    const findings: Finding[] = [];
    for (const req of findFiles(dirname(resolve(ctx.configPath)), (name) => name === "requirements.txt")) {
      const lines = readFileSync(req, "utf8").split(/\r?\n/);
      lines.forEach((line, index) => {
        const dep = line.replace(/#.*/, "").trim();
        if (!dep || dep.startsWith("-") || dep.includes("@")) return;
        if (isExactPythonRequirement(dep)) return;
        findings.push(configFinding(
          this,
          `${rel(req)}:${index + 1}`,
          `Python runtime dependency "${dep}" is not pinned to an exact version. Ranged or unbounded container dependencies can resolve to different code across builds.`,
          "Pin runtime Python dependencies with exact == versions and maintain them through reviewed updates. Use hashes for high-sensitivity container builds where practical.",
          [{ type: "config", label: "requirement", inline: dep }],
        ));
      });
    }
    return findings;
  },
});

function configFinding(
  rule: ConfigRule,
  resource: string,
  message: string,
  remediation: string,
  evidence?: Finding["evidence"],
): Finding {
  return {
    rule_id: rule.id,
    title: rule.title,
    severity: rule.severity,
    resource,
    message,
    remediation,
    probe: rule.probe,
    family: rule.family,
    evidence,
  };
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

function isThirdPartyRuntimeSpec(spec: string): boolean {
  return !spec.startsWith("workspace:") && !spec.startsWith("file:") && !spec.startsWith("link:");
}

function findUp(start: string, names: string[]): string | undefined {
  let cur = start;
  const root = resolve(cur, "/");
  while (true) {
    for (const name of names) {
      const candidate = join(cur, name);
      if (existsSync(candidate)) return candidate;
    }
    if (cur === root) return undefined;
    const parent = dirname(cur);
    if (parent === cur) return undefined;
    cur = parent;
  }
}

function findFiles(dir: string, predicate: (name: string) => boolean): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) out.push(...findFiles(join(dir, entry.name), predicate));
    } else if (entry.isFile() && predicate(entry.name)) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

function isDockerfile(name: string): boolean {
  return name === "Dockerfile" || name.endsWith(".Dockerfile");
}

function isExactPythonRequirement(dep: string): boolean {
  return /^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?==[^<>=~!*]+$/.test(dep) && !dep.includes("*");
}

function rel(path: string): string {
  return relative(process.cwd(), path) || path;
}
