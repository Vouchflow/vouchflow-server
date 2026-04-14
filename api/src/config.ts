export const config = {
  port: parseInt(process.env.API_PORT ?? process.env.PORT ?? '80', 10),
  host: process.env.API_HOST ?? '0.0.0.0',
  apiVersion: process.env.API_VERSION ?? '2026-04-01',
  databaseUrl: requireEnv('DATABASE_URL'),
  redisUrl: process.env.REDIS_URL ?? 'redis://localhost:6379',
  internalHmacSecret: requireEnv('INTERNAL_HMAC_SECRET'),
  nodeEnv: process.env.NODE_ENV ?? 'development',
} as const

function requireEnv(key: string): string {
  const value = process.env[key]
  if (!value) throw new Error(`Missing required environment variable: ${key}`)
  return value
}
