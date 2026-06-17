export function fromBinding(env: { API_TOKEN: string }) {
  // ok: wulf-secret-in-source
  const token = env.API_TOKEN;
  return token;
}
