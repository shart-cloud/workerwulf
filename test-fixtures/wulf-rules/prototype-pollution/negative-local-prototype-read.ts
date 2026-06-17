export function inspect(value: unknown) {
  // ok: wulf-prototype-pollution
  return Object.getPrototypeOf(value);
}
