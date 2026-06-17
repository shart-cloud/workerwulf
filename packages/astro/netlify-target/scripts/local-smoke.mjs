import http from 'node:http';
import { pathToFileURL } from 'node:url';

const callbackPort = Number(process.env.CALLBACK_PORT ?? 9909);
const targetPort = Number(process.env.NETLIFY_PORT ?? 8790);
const callbackPath = `/local-smoke-${Date.now()}`;
const callbackUrl = `http://127.0.0.1:${callbackPort}${callbackPath}`;
const targetUrl = `http://127.0.0.1:${targetPort}/?target=${encodeURIComponent(callbackUrl)}&mode=request&method=POST&body=probe`;
const entryUrl = pathToFileURL(new URL('../.netlify/v1/edge-functions/middleware/entry.mjs', import.meta.url).pathname);

const seen = [];
const callback = http.createServer((req, res) => {
  seen.push({ method: req.method, url: req.url, headers: req.headers });
  res.writeHead(200, {
    'content-type': 'text/plain',
    'x-wulf-callback': 'seen',
  });
  res.end('callback seen\n');
});

await listen(callback, callbackPort);
console.log(`callback: http://127.0.0.1:${callbackPort}`);

try {
  const { default: middleware } = await import(entryUrl.href);
  console.log(`trigger: ${targetUrl}`);
  const res = await middleware(new Request(targetUrl), {
    ip: '127.0.0.1',
    next: () => new Response('next called', { status: 599 }),
  });
  const body = res instanceof Response ? await res.text() : String(res);
  await waitFor(() => Promise.resolve(seen.length > 0), 5_000).catch(() => false);

  console.log(
    JSON.stringify(
      {
        target_status: res instanceof Response ? res.status : undefined,
        target_type: res instanceof Response ? 'Response' : typeof res,
        target_body: body.slice(0, 200),
        callback_url: callbackUrl,
        callback_seen: seen.length > 0,
        callback_requests: seen,
      },
      null,
      2,
    ),
  );

  process.exitCode = seen.length > 0 ? 0 : 1;
} finally {
  callback.close();
}

function listen(server, port) {
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', resolve);
  });
}

async function waitFor(check, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      if (await check()) return;
    } catch {
      // keep polling
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`Timed out after ${timeoutMs}ms`);
}
