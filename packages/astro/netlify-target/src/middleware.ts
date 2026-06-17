import { defineMiddleware } from 'astro:middleware';

export const onRequest = defineMiddleware((context, next) => {
  const target = context.url.searchParams.get('target');
  const mode = context.url.searchParams.get('mode') ?? 'request';

  if (!target) {
    return next();
  }

  const method = context.url.searchParams.get('method') ?? 'GET';
  const body = context.url.searchParams.get('body');
  const targetRequest = new Request(target, {
    method,
    body: body === null ? undefined : body,
    headers: mode === 'headers' ? { 'x-wulf-rewrite': '1' } : undefined,
  });

  if (mode === 'direct') {
    return fetch(targetRequest);
  }

  if (mode === 'url') {
    return context.rewrite(new URL(target));
  }

  return context.rewrite(targetRequest);
});
