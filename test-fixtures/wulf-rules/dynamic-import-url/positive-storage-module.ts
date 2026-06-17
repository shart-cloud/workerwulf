export async function loadFromKv(env: { MODULES: KVNamespace }) {
  const moduleUrl = await env.MODULES.get("active-module");
  if (!moduleUrl) return null;
  // ruleid: wulf-dynamic-import-url
  return import(moduleUrl);
}
