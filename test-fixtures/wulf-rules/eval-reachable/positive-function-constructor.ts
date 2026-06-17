export function compile(code: string) {
  // ruleid: wulf-eval-reachable
  return new Function("env", code);
}
