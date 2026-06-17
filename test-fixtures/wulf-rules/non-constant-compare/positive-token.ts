export function check(providedToken: string, expectedToken: string) {
  // ruleid: wulf-non-constant-compare
  return providedToken === expectedToken;
}
