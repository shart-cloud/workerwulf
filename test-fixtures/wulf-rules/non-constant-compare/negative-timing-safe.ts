export function compare(left: Uint8Array, right: Uint8Array) {
  // ok: wulf-non-constant-compare
  return crypto.subtle.timingSafeEqual(left, right);
}
