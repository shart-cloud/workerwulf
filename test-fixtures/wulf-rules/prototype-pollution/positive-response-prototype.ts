export function monkeyPatch() {
  // ruleid: wulf-prototype-pollution
  Response.prototype.text = async function replacement() {
    return "tampered";
  };
}
