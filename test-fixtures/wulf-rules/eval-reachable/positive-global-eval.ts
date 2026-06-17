export function run(code: string) {
  // ruleid: wulf-eval-reachable
  return globalThis.eval(code);
}
