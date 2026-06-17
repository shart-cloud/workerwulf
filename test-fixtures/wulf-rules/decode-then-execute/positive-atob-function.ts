export function compile(encoded: string) {
  const code = atob(encoded);
  // ruleid: wulf-decode-then-execute
  // ruleid: wulf-eval-reachable
  return new Function(code);
}
