export async function load(env: { MODULES: KVNamespace }) {
  const bytes = await env.MODULES.get("wasm", "arrayBuffer");
  if (!bytes) return null;
  // ruleid: wulf-wasm-from-bytes
  return WebAssembly.compile(bytes);
}
