export async function instantiateStatic(module: WebAssembly.Module) {
  // ok: wulf-wasm-from-bytes
  return WebAssembly.instantiate(module);
}
