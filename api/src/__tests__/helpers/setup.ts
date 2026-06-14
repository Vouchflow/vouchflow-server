// Vitest setup file — runs once per test process. Two jobs:
//
//   1. Stamp the env vars that src/config.ts insists on so test files that
//      transitively import config (via routes/services) don't crash at
//      import-time. Real values are irrelevant; only the presence matters.
//
//   2. Probe whether Postgres + Redis are actually reachable, and surface
//      the result via _VF_TEST_HAS_DB / _VF_TEST_HAS_REDIS. testApp.ts reads
//      those into HAS_DB / HAS_REDIS, and integration suites gate themselves
//      with `HAS_DB ? describe : describe.skip`. Previously this file
//      unconditionally set DATABASE_URL=localhost regardless of what was
//      listening there, so HAS_DB was always true → suites ran → 200+
//      ECONNREFUSED on a laptop without Postgres up.
//
// CI brings up service containers at localhost:5432 / localhost:6379, so the
// probe succeeds and integration suites run there. Locally, run
// `docker compose up -d postgres redis` (see ../../docker-compose.yml) to
// flip both probes green.

import net from 'node:net'

if (!process.env.INTERNAL_HMAC_SECRET) {
  process.env.INTERNAL_HMAC_SECRET = '0'.repeat(64)
}
if (!process.env.WEBHOOK_SECRET_ENCRYPTION_KEY) {
  process.env.WEBHOOK_SECRET_ENCRYPTION_KEY = '0'.repeat(64)
}
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = '0'.repeat(64)
}
if (!process.env.ADMIN_KEY) {
  process.env.ADMIN_KEY = '0'.repeat(64)
}
if (!process.env.VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY) {
  process.env.VOUCHFLOW_SIGNING_KEY_ENCRYPTION_KEY = '0'.repeat(64)
}

const dbHost = process.env.TEST_DB_HOST    ?? 'localhost'
const dbPort = Number(process.env.TEST_DB_PORT    ?? 5432)
const rdHost = process.env.TEST_REDIS_HOST ?? 'localhost'
const rdPort = Number(process.env.TEST_REDIS_PORT ?? 6379)

// Set the URLs before either probe runs — Prisma's client reads DATABASE_URL
// at construction, and the Redis probe needs REDIS_URL on ioredis.
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = `postgresql://vouchflow:test@${dbHost}:${dbPort}/vouchflow_test`
}
if (!process.env.REDIS_URL) {
  process.env.REDIS_URL = `redis://${rdHost}:${rdPort}`
}

// Postgres probe: actually round-trip a query so wrong creds or a missing
// `vouchflow_test` database flip HAS_DB to false instead of "port answers,
// queries fail" — which is the case on this maintainer's box (a different
// Postgres squats on 5432). 1s ceiling so a slow box doesn't silently skip.
async function probePostgres(): Promise<boolean> {
  try {
    const { PrismaClient } = await import('@prisma/client')
    const client = new PrismaClient({ log: [] })
    const ok = await Promise.race([
      client.$queryRaw`SELECT 1`.then(() => true).catch(() => false),
      new Promise<boolean>(r => setTimeout(() => r(false), 1000)),
    ])
    await client.$disconnect().catch(() => {})
    return ok
  } catch {
    return false
  }
}

// Redis probe: TCP-level is enough — no auth in CI/dev, and ioredis would
// otherwise retry forever and never resolve. Short timeout, hard kill on miss.
async function probeRedis(host: string, port: number, timeoutMs = 250): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port })
    let settled = false
    const finish = (ok: boolean) => {
      if (settled) return
      settled = true
      sock.destroy()
      resolve(ok)
    }
    sock.once('connect', () => finish(true))
    sock.once('error',   () => finish(false))
    setTimeout(() => finish(false), timeoutMs)
  })
}

const [hasDb, hasRedis] = await Promise.all([
  probePostgres(),
  probeRedis(rdHost, rdPort),
])

process.env._VF_TEST_HAS_DB    = hasDb    ? '1' : ''
process.env._VF_TEST_HAS_REDIS = hasRedis ? '1' : ''

const tag = (label: string, ok: boolean) =>
  `${label}: ${ok ? '\x1b[32mup\x1b[0m' : '\x1b[33mdown — integration suites will skip\x1b[0m'}`
console.log(`[vitest setup] ${tag('postgres', hasDb)} | ${tag('redis', hasRedis)}`)
