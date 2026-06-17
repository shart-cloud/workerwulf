const targetBase = process.env.TARGET_BASE;
const callbackUrl = process.env.CALLBACK_URL;

if (!targetBase || !callbackUrl) {
  console.error('Usage: TARGET_BASE=https://<deploy-host> CALLBACK_URL=https://<callback-host>/path pnpm trigger:remote');
  process.exit(2);
}

const method = process.env.METHOD ?? 'POST';
const body = process.env.BODY;
const mode = process.env.MODE ?? 'request';
const origin = process.env.ORIGIN;
const url = new URL(targetBase);
url.searchParams.set('target', callbackUrl);
url.searchParams.set('mode', mode);
url.searchParams.set('method', method);
if (body !== undefined) {
  url.searchParams.set('body', body);
}

const init = origin ? { headers: { origin } } : undefined;
const res = await fetch(url, init);
const text = await res.text();

console.log(
  JSON.stringify(
    {
      requested: url.toString(),
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: text.slice(0, 500),
    },
    null,
    2,
  ),
);
