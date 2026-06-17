export function checkHmac(hmac: string, expected: string) {
  // ruleid: wulf-non-constant-compare
  return hmac !== expected;
}
