export function token() {
  const bytes = new Uint8Array(16);
  // ok: wulf-insecure-random
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
