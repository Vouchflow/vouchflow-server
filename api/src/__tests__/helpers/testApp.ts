// Integration-test harness. Spins up a minimal Fastify instance with selected
// routes + the real apiKeyAuth plugin against the real Prisma client. Skips
// the global rate-limit plugin since it requires Redis and isn't what these
// tests are about. The app is short-lived per test file.
//
// Tests using this helper require a real Postgres pointed at by DATABASE_URL.
// In CI the workflow brings up postgres:16-alpine via service containers
// (server.yml). Locally:
//   sudo docker run -d --rm --name vf-test-pg -p 15432:5432 \
//     -e POSTGRES_USER=vouchflow -e POSTGRES_PASSWORD=test \
//     -e POSTGRES_DB=vouchflow_test postgres:16-alpine
//   DATABASE_URL=postgres://vouchflow:test@localhost:15432/vouchflow_test \
//     npx prisma db push
//
// Tests gracefully describe.skip themselves when DATABASE_URL is unset, so
// `npm test` in a bare local checkout still runs the unit suite.

import Fastify, { FastifyInstance, FastifyPluginAsync } from 'fastify'
import crypto from 'node:crypto'
import { prisma } from '../../lib/prisma.js'

export const HAS_DB = Boolean(process.env.DATABASE_URL)

/** Mints a sandbox-keyed Customer row directly via Prisma — bypasses
 *  POST /v1/customers (which talks to the web service). */
export async function createSandboxCustomer(opts: {
  email?: string
  androidPackageName?: string | null
  androidSigningKeySha256?: string | null
  iosTeamId?: string | null
  iosBundleId?: string | null
} = {}) {
  // Apps refactor: a customer's sandbox keys and attestation params live on
  // their default App now. createSandboxCustomer creates both in a single
  // Prisma transaction and returns the App alongside the Customer so callers
  // that need request.appId fixtures (most route tests) have it.
  const id = `cust_${crypto.randomBytes(8).toString('hex')}`
  const sandboxWriteKey = `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`
  const sandboxReadKey  = `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`
  const customer = await prisma.customer.create({
    data: {
      id,
      email: opts.email ?? `${id}@test.local`,
      apps: {
        create: {
          name: 'Default App',
          slug: 'default',
          sandboxWriteKey,
          sandboxReadKey,
          androidPackageName:      opts.androidPackageName ?? null,
          androidSigningKeySha256: opts.androidSigningKeySha256 ?? null,
          iosTeamId:               opts.iosTeamId ?? null,
          iosBundleId:             opts.iosBundleId ?? null,
          signPayloadMinConfidence: 'high',
        },
      },
    },
    include: { apps: true },
  })
  const app = customer.apps[0]!
  return { customer, app, sandboxWriteKey, sandboxReadKey }
}

export async function createLiveKey(
  customerId: string,
  scope: 'write' | 'read',
  opts: { deprecated?: boolean; deprecatedAt?: Date | null; appId?: string } = {},
) {
  // chunk1 fixture update: live keys belong to an App. If caller doesn't pass
  // appId explicitly, look up the customer's default app.
  let appId = opts.appId
  if (!appId) {
    const app = await prisma.app.findFirst({
      where: { customerId, archivedAt: null },
      orderBy: { createdAt: 'asc' },
    })
    if (!app) throw new Error(`createLiveKey: customer ${customerId} has no app — call createSandboxCustomer first`)
    appId = app.id
  }
  const rawKey = scope === 'write'
    ? `vsk_live_${crypto.randomBytes(20).toString('hex')}`
    : `vsk_live_read_${crypto.randomBytes(20).toString('hex')}`
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex')
  const apiKey = await prisma.apiKey.create({
    data: {
      customerId,
      appId,
      keyHash,
      scope,
      deprecated:   opts.deprecated   ?? false,
      deprecatedAt: opts.deprecatedAt ?? null,
    },
  })
  return { apiKey, rawKey }
}

/** Truncates per-test Customer / ApiKey / Device rows. Apps cascade-delete
 *  with Customer, so listing customers last in the TRUNCATE order is enough.
 *  Other tables cascade via FK or are left alone (idempotency_records,
 *  network_events). */
export async function cleanDb(): Promise<void> {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "verifications", "devices", "api_keys", "webhook_deliveries", "webhook_endpoints", "idempotency_records", "apps", "customers" RESTART IDENTITY CASCADE'
  )
}

/** Mint a Device row directly. Bypasses the enroll route. Uses the customer's
 *  default app if appId isn't supplied. */
export async function createDevice(
  customerId: string,
  opts: { platform?: string; status?: string; enrolledAt?: Date; isSandbox?: boolean; appId?: string } = {},
) {
  let appId = opts.appId
  if (!appId) {
    const app = await prisma.app.findFirst({
      where: { customerId, archivedAt: null },
      orderBy: { createdAt: 'asc' },
    })
    if (!app) throw new Error(`createDevice: customer ${customerId} has no app — call createSandboxCustomer first`)
    appId = app.id
  }
  return prisma.device.create({
    data: {
      customerId,
      appId,
      deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
      publicKey: crypto.randomBytes(64).toString('base64'),
      keyFingerprint: crypto.randomBytes(32).toString('hex'),
      platform: opts.platform ?? 'android',
      status: opts.status ?? 'active',
      enrolledAt: opts.enrolledAt ?? new Date(),
      isSandbox: opts.isSandbox ?? true,
    },
  })
}

/** Mint a Verification row directly. Confidence + completedAt control how
 *  the row contributes to /stats aggregations. */
export async function createVerification(
  customerId: string,
  deviceId: string,
  opts: {
    state?: string
    confidence?: 'high' | 'medium' | 'low' | null
    biometricUsed?: boolean
    fallbackUsed?: boolean
    createdAt?: Date
    completedAt?: Date | null
    isSandbox?: boolean
    appId?: string
  } = {},
) {
  let appId = opts.appId
  if (!appId) {
    const app = await prisma.app.findFirst({
      where: { customerId, archivedAt: null },
      orderBy: { createdAt: 'asc' },
    })
    if (!app) throw new Error(`createVerification: customer ${customerId} has no app — call createSandboxCustomer first`)
    appId = app.id
  }
  const createdAt = opts.createdAt ?? new Date()
  return prisma.verification.create({
    data: {
      customerId,
      appId,
      deviceId,
      sessionId: `ses_${crypto.randomBytes(8).toString('hex')}`,
      challenge: crypto.randomBytes(32).toString('base64'),
      state: opts.state ?? 'COMPLETED',
      context: 'login',
      biometricUsed: opts.biometricUsed ?? true,
      fallbackUsed: opts.fallbackUsed ?? false,
      confidence: opts.confidence === undefined ? 'high' : opts.confidence,
      expiresAt: new Date(createdAt.getTime() + 60_000),
      createdAt,
      completedAt: opts.completedAt === undefined ? new Date(createdAt.getTime() + 1_500) : opts.completedAt,
      isSandbox: opts.isSandbox ?? true,
    },
  })
}

/** Builds a minimal Fastify instance with a single test plugin. The plugin
 *  registers whatever routes the caller wants, gets the apiKeyAuth plugin
 *  pre-applied if `requireAuth` is set, and the rate-limit plugin is OMITTED
 *  (we're not testing rate limits and don't want a Redis dependency). */
export async function buildTestApp(plugin: FastifyPluginAsync): Promise<FastifyInstance> {
  const app = Fastify({ logger: false, trustProxy: true })
  await app.register(plugin)
  await app.ready()
  return app
}
