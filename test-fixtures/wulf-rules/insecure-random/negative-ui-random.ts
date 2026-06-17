export function pickColor() {
  // ok: wulf-insecure-random
  const hue = Math.random() * 360;
  return `hsl(${hue}, 90%, 50%)`;
}
