export async function load(env: { WASM_BYTES: ArrayBuffer }) {
  const bytes = env.WASM_BYTES;
  // ruleid: wulf-wasm-from-bytes
  return WebAssembly.instantiate(bytes);
}
