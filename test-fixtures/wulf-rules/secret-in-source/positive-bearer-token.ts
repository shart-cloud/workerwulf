export function authHeader() {
  // ruleid: wulf-secret-in-source
  const token = "Bearer abc.def.ghi";
  return { authorization: token };
}
