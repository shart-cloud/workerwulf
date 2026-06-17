export function display(encoded: string) {
  const decoded = atob(encoded);
  // ok: wulf-decode-then-execute
  return new Response(decoded);
}
