declare module "*.wasm" {
  const module: WebAssembly.Module;
  export default module;
}

declare module "oxc-parser/src-js/wrap.js" {
  export function wrap<T>(result: T): { program: unknown; errors: Array<{ message: string }> };
}
