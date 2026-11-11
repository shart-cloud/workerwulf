import type { ProbeHttp, ProbeResponse } from "./http.js";

/**
 * Black-box platform fingerprinting for Cloudflare Workers.
 *
 * Every observation becomes a Signal that votes for one hypothesis with a
 * weight. Decisive signals (hostname suffixes, Workers-only error pages)
 * settle the verdict on their own; the rest are summed into a worker-vs-origin
 * score. Nothing here is a vulnerability — rules consume the fingerprint.
 */

export type Platform =
  | "cloudflare-workers"
  | "cloudflare-pages"
  | "cloudflare-proxied-origin"
  | "cloudflare-unknown"
  | "celld"
  | "not-cloudflare";

export type Hypothesis = "cloudflare" | "worker" | "pages" | "origin" | "celld" | "not-cloudflare";

export interface Signal {
  id: string;
  points_to: Hypothesis;
  /** 0–100. 100 means decisive. */
  weight: number;
  detail: string;
}

export interface Fingerprint {
  target: string;
  platform: Platform;
  confidence: "high" | "medium" | "low";
  signals: Signal[];
  /** Cloudflare data-centre code from cf-ray or /cdn-cgi/trace. */
  colo?: string;
  frameworks: string[];
  features: {
    access_protected: boolean;
    smart_placement?: string;
    static_assets: boolean;
  };
  /** Responses later rules reuse instead of re-requesting. */
  baseline: ProbeResponse;
  /** A random, certainly-nonexistent path — the soft-404 reference. */
  not_found: ProbeResponse;
  /** GET-only inputs chosen to make naive handlers throw. */
  error_probes: ProbeResponse[];
}

const ORIGIN_HEADERS: [RegExp, string][] = [
  [/^x-amz-(cf-id|request-id|id-2)$/, "AWS"],
  [/^x-goog-/, "Google Cloud"],
  [/^x-vercel-/, "Vercel"],
  [/^x-nf-request-id$/, "Netlify"],
  [/^x-github-request-id$/, "GitHub Pages"],
  [/^x-served-by$/, "Fastly/Varnish"],
  [/^x-azure-ref$/, "Azure Front Door"],
  [/^x-aspnet-version$/, "ASP.NET"],
  [/^x-drupal-/, "Drupal"],
  [/^x-litespeed-/, "LiteSpeed"],
];

const ORIGIN_COOKIES: [RegExp, string][] = [
  [/\bPHPSESSID=/, "PHP"],
  [/\bJSESSIONID=/, "Java servlet"],
  [/\bASP\.NET_SessionId=/, "ASP.NET"],
  [/\bwordpress_/, "WordPress"],
  [/\blaravel_session=/, "Laravel"],
];

const ORIGIN_SERVER_TOKENS = /\b(nginx|apache|iis|caddy|envoy|gunicorn|uvicorn|openresty|litespeed|kestrel)\b/i;

const WORKER_ERROR_PAGES: [RegExp, string][] = [
  [/Error 1101|Worker threw exception/i, "1101 Worker threw exception"],
  [/Error 1102|Worker exceeded resource limits/i, "1102 Worker exceeded resource limits"],
  [/Error 1027|Worker exceeded .*daily request limit/i, "1027 Worker request limit"],
  [/Error 1042/i, "1042 Worker-to-Worker fetch refused"],
];

/** Frameworks commonly deployed on Workers, keyed on low-ambiguity markers. */
const FRAMEWORKS: { name: string; test: (r: ProbeResponse) => boolean }[] = [
  {
    name: "Next.js (OpenNext)",
    test: (r) => r.headers["x-opennext"] !== undefined,
  },
  {
    name: "Next.js",
    test: (r) =>
      /next\.js/i.test(r.headers["x-powered-by"] ?? "") ||
      r.headers["x-nextjs-cache"] !== undefined ||
      /\/_next\/static\//.test(r.body),
  },
  {
    name: "Astro",
    test: (r) => /<meta[^>]+generator[^>]+Astro/i.test(r.body) || /\/_astro\//.test(r.body),
  },
  { name: "SvelteKit", test: (r) => /\/_app\/immutable\//.test(r.body) },
  { name: "Nuxt", test: (r) => /\/_nuxt\//.test(r.body) },
  { name: "React Router", test: (r) => /__reactRouterContext/.test(r.body) },
  { name: "Remix", test: (r) => /__remixContext/.test(r.body) },
  { name: "Qwik", test: (r) => /q:container|qwikloader/.test(r.body) },
];

/** Hono's built-in notFound handler: exact body + content-type. */
function isHonoNotFound(r: ProbeResponse): boolean {
  return (
    r.status === 404 &&
    r.body === "404 Not Found" &&
    /^text\/plain;\s*charset=utf-8$/i.test(r.headers["content-type"] ?? "")
  );
}

function isCloudflareResponse(r: ProbeResponse): boolean {
  return /^cloudflare$/i.test(r.headers["server"] ?? "") || r.headers["cf-ray"] !== undefined;
}

export function isAccessRedirect(r: ProbeResponse): boolean {
  const loc = r.headers["location"] ?? "";
  return (
    r.status >= 300 &&
    r.status < 400 &&
    (/\.cloudflareaccess\.com\//i.test(loc) || /\/cdn-cgi\/access\/login/i.test(loc))
  );
}

/** Requests the fingerprint needs, in the order sent. Exported for docs/tests. */
export function errorProbePaths(nonce: string): string[] {
  return [
    // Lone/invalid percent-escapes: decodeURIComponent() throws URIError.
    `/wulf-${nonce}/%E0%A4%A`,
    `/?wulf=%E0%A4%A&n=${nonce}`,
    // Prototype-pollution-shaped keys trip naive query→object merges.
    `/?__proto__[wulf]=1&constructor[prototype][wulf]=1&n=${nonce}`,
  ];
}

export async function fingerprint(
  http: ProbeHttp,
  target: URL,
  nonce: () => string,
): Promise<Fingerprint> {
  const origin = target.origin;
  const signals: Signal[] = [];
  const add = (s: Signal): void => {
    if (!signals.some((x) => x.id === s.id)) signals.push(s);
  };

  const baseline = await http.follow({ url: target.toString() });
  const nf = nonce();
  const notFound = await http.request({ url: `${origin}/wulf-${nf}` });
  const staticMiss = await http.request({ url: `${origin}/wulf-${nf}.css` });
  const errorProbes: ProbeResponse[] = [];
  for (const path of errorProbePaths(nonce())) {
    errorProbes.push(await http.request({ url: `${origin}${path}` }));
  }

  const host = target.hostname.toLowerCase();
  if (host.endsWith(".workers.dev")) {
    add({ id: "host-workers-dev", points_to: "worker", weight: 100, detail: `hostname ${host} is a workers.dev route` });
  }
  if (host.endsWith(".pages.dev")) {
    add({ id: "host-pages-dev", points_to: "pages", weight: 100, detail: `hostname ${host} is a pages.dev deployment` });
  }

  const observed = [baseline, notFound, staticMiss, ...errorProbes];

  // celld (self-hosted Workers/Durable Objects) reserves this exact path on its
  // public listener; Cloudflare does not. It's the cleanest Worker-vs-celld tell.
  for (const r of observed) {
    if (r.headers["x-celld-overload"] !== undefined) {
      add({ id: "celld-overload-header", points_to: "celld", weight: 60, detail: `x-celld-overload: ${r.headers["x-celld-overload"]}` });
    }
  }
  if (!host.endsWith(".workers.dev") && !host.endsWith(".pages.dev")) {
    const health = await http.request({ url: `${origin}/.well-known/celld/health` });
    if ((health.status === 200 || health.status === 503) && /^\s*\{"ok":(true|false)\}\s*$/.test(health.body)) {
      add({ id: "celld-health", points_to: "celld", weight: 100, detail: `/.well-known/celld/health → ${health.status} ${health.body.trim()} (celld reserved path)` });
    }
  }

  const onCloudflare = observed.some(isCloudflareResponse);
  let colo: string | undefined;
  for (const r of observed) {
    const ray = r.headers["cf-ray"];
    const m = ray?.match(/-([A-Z]{3})$/);
    if (m) colo = m[1];
  }
  if (onCloudflare) {
    add({
      id: "cf-edge",
      points_to: "cloudflare",
      weight: 100,
      detail: `server: cloudflare / cf-ray present${colo ? ` (colo ${colo})` : ""}`,
    });
  }

  // /cdn-cgi/trace confirms a Cloudflare zone and names the colo even when
  // response headers are stripped by an upstream proxy.
  if (onCloudflare || host.endsWith(".workers.dev") || host.endsWith(".pages.dev")) {
    const trace = await http.request({ url: `${origin}/cdn-cgi/trace` });
    const traceColo = trace.status === 200 ? trace.body.match(/^colo=([A-Z]{3})$/m)?.[1] : undefined;
    if (traceColo) {
      colo ??= traceColo;
      add({ id: "cdn-cgi-trace", points_to: "cloudflare", weight: 100, detail: `/cdn-cgi/trace answered (colo=${traceColo})` });
    }
  }

  for (const r of observed) {
    for (const [re, label] of WORKER_ERROR_PAGES) {
      if (re.test(r.body)) {
        add({ id: `cf-error-${label.slice(0, 4)}`, points_to: "worker", weight: 100, detail: `${label} page at ${pathOf(r.url)}` });
      }
    }
  }

  const placement = observed.map((r) => r.headers["cf-placement"]).find(Boolean);
  if (placement) {
    add({ id: "cf-placement", points_to: "worker", weight: 60, detail: `cf-placement: ${placement} (Smart Placement is a Workers feature)` });
  }

  // Edge cache participation: a proxied origin's static-extension miss is
  // cache-eligible (cf-cache-status MISS/EXPIRED/DYNAMIC/BYPASS). A Worker
  // that builds its own Response emits no cf-cache-status at all.
  if (onCloudflare) {
    const cacheStatus = staticMiss.headers["cf-cache-status"];
    if (cacheStatus) {
      add({ id: "edge-cache-status", points_to: "origin", weight: 25, detail: `cf-cache-status: ${cacheStatus} on a static-extension miss` });
    } else if (!baseline.headers["cf-cache-status"] && !notFound.headers["cf-cache-status"]) {
      add({ id: "no-edge-cache-status", points_to: "worker", weight: 20, detail: "no cf-cache-status on baseline, 404 or static-extension miss" });
    }
  }

  for (const r of observed) {
    for (const name of Object.keys(r.headers)) {
      for (const [re, label] of ORIGIN_HEADERS) {
        if (re.test(name)) {
          add({ id: `origin-header-${label}`, points_to: "origin", weight: 40, detail: `${name} header suggests a ${label} origin` });
        }
      }
    }
    const cookies = r.headers["set-cookie"] ?? "";
    for (const [re, label] of ORIGIN_COOKIES) {
      if (re.test(cookies)) {
        add({ id: `origin-cookie-${label}`, points_to: "origin", weight: 40, detail: `${label} session cookie` });
      }
    }
    const server = r.headers["server"] ?? "";
    const via = r.headers["via"] ?? "";
    const token = (server.match(ORIGIN_SERVER_TOKENS) ?? via.match(ORIGIN_SERVER_TOKENS))?.[1];
    if (token) {
      add({ id: `origin-server-${token.toLowerCase()}`, points_to: "origin", weight: 40, detail: `origin server token "${token}" leaked via server/via` });
    }
    const powered = r.headers["x-powered-by"];
    if (powered && !/next\.js/i.test(powered)) {
      add({ id: "origin-x-powered-by", points_to: "origin", weight: 30, detail: `x-powered-by: ${powered}` });
    }
  }

  const frameworks = FRAMEWORKS.filter((f) => observed.some(f.test)).map((f) => f.name);
  if (isHonoNotFound(notFound)) {
    frameworks.push("Hono");
    add({ id: "hono-404", points_to: "worker", weight: 30, detail: "Hono default notFound body (Hono is Workers-first)" });
  }
  if (frameworks.includes("Next.js (OpenNext)")) {
    add({ id: "opennext", points_to: "worker", weight: 60, detail: "x-opennext header (OpenNext Cloudflare adapter)" });
  }

  // Workers Static Assets: assets are served before the Worker runs, with a
  // strong quoted ETag and no cf-cache-status.
  const staticAssets =
    /^"[0-9a-f]{16,64}"$/.test(baseline.headers["etag"] ?? "") &&
    !baseline.headers["cf-cache-status"] &&
    onCloudflare;
  if (staticAssets) {
    add({ id: "static-assets-etag", points_to: "worker", weight: 15, detail: `strong hex ETag ${baseline.headers["etag"]} without cf-cache-status` });
  }

  const accessProtected = isAccessRedirect(baseline);
  if (accessProtected) {
    add({ id: "cf-access", points_to: "cloudflare", weight: 100, detail: "baseline redirects to Cloudflare Access login" });
  }

  const celldDetected = signals.some((s) => s.id === "celld-health");
  if (!onCloudflare && !celldDetected && !signals.some((s) => s.id === "cdn-cgi-trace")) {
    add({ id: "no-cf-edge", points_to: "not-cloudflare", weight: 100, detail: "no server: cloudflare, cf-ray, or /cdn-cgi/trace" });
  }

  const { platform, confidence } = verdict(signals);
  return {
    target: target.toString(),
    platform,
    confidence,
    signals,
    colo,
    frameworks,
    features: { access_protected: accessProtected, smart_placement: placement, static_assets: staticAssets },
    baseline,
    not_found: notFound,
    error_probes: errorProbes,
  };
}

export function verdict(signals: Signal[]): { platform: Platform; confidence: Fingerprint["confidence"] } {
  const decisive = (h: Hypothesis): boolean => signals.some((s) => s.points_to === h && s.weight >= 100);
  if (decisive("celld")) return { platform: "celld", confidence: "high" };
  if (decisive("pages")) return { platform: "cloudflare-pages", confidence: "high" };
  if (decisive("worker")) return { platform: "cloudflare-workers", confidence: "high" };
  if (decisive("not-cloudflare") && !decisive("cloudflare")) {
    return { platform: "not-cloudflare", confidence: "medium" };
  }
  const sum = (h: Hypothesis): number =>
    signals.filter((s) => s.points_to === h).reduce((n, s) => n + s.weight, 0);
  const score = sum("worker") - sum("origin");
  const confidence = Math.abs(score) >= 50 ? "high" : Math.abs(score) >= 25 ? "medium" : "low";
  if (score > 0) return { platform: "cloudflare-workers", confidence };
  if (score < 0) return { platform: "cloudflare-proxied-origin", confidence };
  return { platform: "cloudflare-unknown", confidence: "low" };
}

export function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return `${u.pathname}${u.search}`;
  } catch {
    return url;
  }
}
