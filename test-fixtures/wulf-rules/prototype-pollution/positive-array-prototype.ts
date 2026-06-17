export function monkeyPatch() {
  // ruleid: wulf-prototype-pollution
  Array.prototype.map = function replacement() {
    return [];
  };
}
