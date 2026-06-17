export default {
  async fetch(req: Request) {
    const bytes = await req.arrayBuffer();
    // ruleid: wulf-wasm-from-bytes
    const mod = await WebAssembly.compile(bytes);
    return new Response(String(mod));
  },
};
