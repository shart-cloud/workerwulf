export function run(encoded: string) {
  // ruleid: wulf-decode-then-execute
  // ruleid: wulf-eval-reachable
  return eval(atob(encoded));
}
