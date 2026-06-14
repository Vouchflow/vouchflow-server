// Vitest setup file — runs once per test process. Two jobs:
//
//   1. Stamp the env vars that src/config.ts insists on so test files that
//      transitively import config (via routes/services) don't crash at
//      import-time. Real values are irrelevant; only the presence matters.
//
//   2. Probe whether Postgres is actually reachable, and surface the result
//      via _VF_TEST_HAS_DB. testApp.ts reads that into HAS_DB, and the
//      integration suites gate themselves with `HAS_DB ? describe : describe.skip`.
//      Previously this file unconditionally set DATABASE_URL=localhost
//      regardless of what was listening there, so HAS_DB was always true →
//      suites ran → 200+ ECONNREFUSED on a laptop without Postgres up.
//
// Used to also probe Redis when BullMQ + Redis-backed rate-limit/session
// were in the dependency graph. The api-server doesn't touch Redis anymore
// (see services/anomaly.ts + services/webhooks.ts retry tick); only Postgres
// is required to run the integration suites.

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

const dbHost = process.env.TEST_DB_HOST ?? 'localhost'
const dbPort = Number(process.env.TEST_DB_PORT ?? 5432)

// DATABASE_URL must be set before the probe — Prisma's client reads it at
// construction. If Postgres isn't actually reachable for these creds, the
// probe fails and HAS_DB stays false, so no integration test attempts a query.
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = `postgresql://vouchflow:test@${dbHost}:${dbPort}/vouchflow_test`
}

// Postgres probe: round-trip a real query so wrong creds or a missing
// `vouchflow_test` database flip HAS_DB to false instead of letting the
// "port answers, queries fail" footgun bite (the case on this maintainer's
// box, where a different Postgres squats on 5432). 1s ceiling.
async function probePostgres(): Promise<boolean> {
  try {
    const { PrismaClient } = await import('@prisma/client')
    const client = new PrismaClient({ log: [] })
    const ok = await Promise.race([
      client.$queryRaw`SELECT 1`.then(() => true).catch(() => false),
      new Promise<boolean>((r) => setTimeout(() => r(false), 1000)),
    ])
    await client.$disconnect().catch(() => {})
    return ok
  } catch {
    return false
  }
}

const hasDb = await probePostgres()
process.env._VF_TEST_HAS_DB = hasDb ? '1' : ''

console.log(
  `[vitest setup] postgres: ${hasDb ? '\x1b[32mup\x1b[0m' : '\x1b[33mdown — integration suites will skip\x1b[0m'}`,
)
