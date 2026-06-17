export function databaseUrl(env: { DATABASE_URL: string }) {
  // ok: wulf-hardcoded-conn-string
  const dsn = env.DATABASE_URL;
  return dsn;
}
