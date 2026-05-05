import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import statsRoute from '../stats.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
  createDevice,
  createVerification,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// /v1/customers/:id/stats and /v1/verifications back the dashboard's
// overview cards + recent-activity table. Until v2.0.0 these returned 404
// (route didn't exist) and the dashboard rendered hardcoded zeros. Cover
// the aggregation correctness and the per-customer scoping.

d('GET /v1/customers/:id/stats', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(statsRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('returns zeros + nulls for a customer with no devices/verifications', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as Record<string, unknown>
    expect(body).toMatchObject({
      verificationCount: 0,
      deviceCount:       0,
      highConfidencePct: null,
      successRatePct:    null,
    })
    expect(Array.isArray(body.dailyBreakdown)).toBe(true)
  })

  it('counts devices and completed verifications, computes confidence %', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    // 3 high, 1 medium, 1 low → 60% high
    await createVerification(customer.id, dev.id, { confidence: 'high' })
    await createVerification(customer.id, dev.id, { confidence: 'high' })
    await createVerification(customer.id, dev.id, { confidence: 'high' })
    await createVerification(customer.id, dev.id, { confidence: 'medium' })
    await createVerification(customer.id, dev.id, { confidence: 'low' })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    const body = res.json() as { verificationCount: number; deviceCount: number; highConfidencePct: number }
    expect(body.verificationCount).toBe(5)
    expect(body.deviceCount).toBe(1)
    expect(body.highConfidencePct).toBeCloseTo(60.0, 5)
  })

  it('computes successRatePct = success / (success + terminal failure)', async () => {
    // 3 successes, 1 failure → 75%. INITIATED is in-flight and excluded.
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    await createVerification(customer.id, dev.id, { state: 'COMPLETED' })
    await createVerification(customer.id, dev.id, { state: 'COMPLETED' })
    await createVerification(customer.id, dev.id, { state: 'FALLBACK_COMPLETE' })
    await createVerification(customer.id, dev.id, { state: 'FAILED' })
    await createVerification(customer.id, dev.id, { state: 'INITIATED', completedAt: null })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { successRatePct: number }).successRatePct).toBeCloseTo(75.0, 5)
  })

  it('dedupes device count by keyFingerprint (re-enrollments do not inflate)', async () => {
    // The enroll route upserts on deviceToken, so an app reinstall that
    // doesn't restore the cached token re-enrolls under the *same* attestation
    // public key but a fresh deviceToken — creating a second 'active' row.
    // The dashboard counter should collapse those.
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const sharedFp = 'fp_' + 'a'.repeat(60)
    await prisma.device.create({
      data: {
        customerId: customer.id, deviceToken: 'dvt_a', publicKey: 'pk_a',
        keyFingerprint: sharedFp, platform: 'android', status: 'active', enrolledAt: new Date(),
      },
    })
    await prisma.device.create({
      data: {
        customerId: customer.id, deviceToken: 'dvt_b', publicKey: 'pk_a',
        keyFingerprint: sharedFp, platform: 'android', status: 'active', enrolledAt: new Date(),
      },
    })
    await prisma.device.create({
      data: {
        customerId: customer.id, deviceToken: 'dvt_c', publicKey: 'pk_b',
        keyFingerprint: 'fp_' + 'b'.repeat(60), platform: 'android', status: 'active', enrolledAt: new Date(),
      },
    })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { deviceCount: number }).deviceCount).toBe(2)
  })

  it('excludes devices enrolled outside the requested range', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000)
    const yesterday  = new Date(Date.now() -      24 * 60 * 60 * 1000)
    await createDevice(customer.id, { enrolledAt: tenDaysAgo })
    await createDevice(customer.id, { enrolledAt: yesterday })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats?range=7d`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { deviceCount: number }).deviceCount).toBe(1)
  })

  it('excludes verifications outside the requested range', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000)
    const yesterday  = new Date(Date.now() -      24 * 60 * 60 * 1000)
    await createVerification(customer.id, dev.id, { createdAt: tenDaysAgo })
    await createVerification(customer.id, dev.id, { createdAt: yesterday })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats?range=7d`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { verificationCount: number }).verificationCount).toBe(1)
  })

  it('rejects invalid range values', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats?range=2y`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(400)
  })

  it('scopes to the auth\'d customer (no cross-tenant leak via :id param)', async () => {
    const a = await createSandboxCustomer()
    const b = await createSandboxCustomer()
    const devB = await createDevice(b.customer.id)
    await createVerification(b.customer.id, devB.id, { confidence: 'high' })

    // a's key on b's URL — must return a's stats (zero), not b's (one).
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${b.customer.id}/stats`,
      headers: { authorization: `Bearer ${a.sandboxWriteKey}` },
    })
    expect((res.json() as { verificationCount: number }).verificationCount).toBe(0)
  })

  it('excludes verifications still INITIATED (only completed/failed paths count)', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    await createVerification(customer.id, dev.id, { state: 'INITIATED', completedAt: null })
    await createVerification(customer.id, dev.id, { state: 'COMPLETED' })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { verificationCount: number }).verificationCount).toBe(1)
  })

  it('rejects requests without an API key', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats`,
    })
    expect(res.statusCode).toBe(401)
  })

  it('env=sandbox excludes live rows; env=production excludes sandbox rows', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const sandboxDev = await createDevice(customer.id, { isSandbox: true })
    const liveDev    = await createDevice(customer.id, { isSandbox: false })
    await createVerification(customer.id, sandboxDev.id, { confidence: 'high', isSandbox: true })
    await createVerification(customer.id, sandboxDev.id, { confidence: 'high', isSandbox: true })
    await createVerification(customer.id, liveDev.id,    { confidence: 'high', isSandbox: false })

    const sandboxRes = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats?env=sandbox`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    const sandboxBody = sandboxRes.json() as { verificationCount: number; deviceCount: number }
    expect(sandboxBody.verificationCount).toBe(2)
    expect(sandboxBody.deviceCount).toBe(1)

    const prodRes = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats?env=production`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    const prodBody = prodRes.json() as { verificationCount: number; deviceCount: number }
    expect(prodBody.verificationCount).toBe(1)
    expect(prodBody.deviceCount).toBe(1)
  })

  it('rejects an unknown env value', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/stats?env=staging`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(400)
  })
})

d('GET /v1/verifications', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(statsRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('returns recent verifications, newest-first', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    const old = await createVerification(customer.id, dev.id, {
      createdAt: new Date(Date.now() - 60_000),
    })
    const young = await createVerification(customer.id, dev.id, {
      createdAt: new Date(),
    })

    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    const body = res.json() as { rows: Array<{ sessionId: string }> }
    expect(body.rows.length).toBe(2)
    expect(body.rows[0].sessionId).toBe(young.sessionId)
    expect(body.rows[1].sessionId).toBe(old.sessionId)
  })

  it('filters by confidence', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    await createVerification(customer.id, dev.id, { confidence: 'high' })
    await createVerification(customer.id, dev.id, { confidence: 'low' })

    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications?confidence=high',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    const body = res.json() as { rows: Array<{ confidence: string }> }
    expect(body.rows.length).toBe(1)
    expect(body.rows[0].confidence).toBe('high')
  })

  it('filters by platform (joins through device)', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const ios     = await createDevice(customer.id, { platform: 'ios' })
    const android = await createDevice(customer.id, { platform: 'android' })
    await createVerification(customer.id, ios.id)
    await createVerification(customer.id, android.id)

    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications?platform=ios',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    const body = res.json() as { rows: Array<{ platform: string }> }
    expect(body.rows.length).toBe(1)
    expect(body.rows[0].platform).toBe('ios')
  })

  it('respects limit + offset for pagination', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    for (let i = 0; i < 5; i++) {
      await createVerification(customer.id, dev.id, {
        createdAt: new Date(Date.now() - i * 1000),
      })
    }
    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications?limit=2&offset=2',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { rows: unknown[] }).rows.length).toBe(2)
  })

  it('rejects an unknown confidence enum value', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications?confidence=banana',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(400)
  })

  it('scopes to the auth\'d customer', async () => {
    const a = await createSandboxCustomer()
    const b = await createSandboxCustomer()
    const devB = await createDevice(b.customer.id)
    await createVerification(b.customer.id, devB.id)

    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications',
      headers: { authorization: `Bearer ${a.sandboxWriteKey}` },
    })
    expect((res.json() as { rows: unknown[] }).rows.length).toBe(0)
  })

  it('result=verified returns successes at high confidence only', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    await createVerification(customer.id, dev.id, { state: 'COMPLETED',          confidence: 'high'   })
    await createVerification(customer.id, dev.id, { state: 'COMPLETED',          confidence: 'medium' })
    await createVerification(customer.id, dev.id, { state: 'FALLBACK_COMPLETE',  confidence: 'high'   })
    await createVerification(customer.id, dev.id, { state: 'FAILED',             confidence: 'high'   })

    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications?result=verified',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { rows: unknown[] }).rows.length).toBe(2)
  })

  it('result=degraded returns successes at medium/low confidence only', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    await createVerification(customer.id, dev.id, { state: 'COMPLETED', confidence: 'high'   })
    await createVerification(customer.id, dev.id, { state: 'COMPLETED', confidence: 'medium' })
    await createVerification(customer.id, dev.id, { state: 'COMPLETED', confidence: 'low'    })

    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications?result=degraded',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { rows: unknown[] }).rows.length).toBe(2)
  })

  it('result=failed returns terminal-failure states (FAILED, EXPIRED, FALLBACK_LOCKED, FALLBACK_EXPIRED)', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    await createVerification(customer.id, dev.id, { state: 'COMPLETED' })
    await createVerification(customer.id, dev.id, { state: 'FAILED' })
    await createVerification(customer.id, dev.id, { state: 'EXPIRED' })
    await createVerification(customer.id, dev.id, { state: 'FALLBACK_LOCKED' })
    await createVerification(customer.id, dev.id, { state: 'FALLBACK_EXPIRED' })

    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications?result=failed',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((res.json() as { rows: unknown[] }).rows.length).toBe(4)
  })

  it('rejects an unknown result value', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: '/v1/verifications?result=banana',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(400)
  })

  it('env=sandbox returns only sandbox rows; env=production returns only live rows', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const sandboxDev = await createDevice(customer.id, { isSandbox: true })
    const liveDev    = await createDevice(customer.id, { isSandbox: false })
    await createVerification(customer.id, sandboxDev.id, { isSandbox: true })
    await createVerification(customer.id, liveDev.id,    { isSandbox: false })
    await createVerification(customer.id, liveDev.id,    { isSandbox: false })

    const sandboxRes = await app.inject({
      method: 'GET',
      url: '/v1/verifications?env=sandbox',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((sandboxRes.json() as { rows: unknown[] }).rows.length).toBe(1)

    const prodRes = await app.inject({
      method: 'GET',
      url: '/v1/verifications?env=production',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect((prodRes.json() as { rows: unknown[] }).rows.length).toBe(2)
  })
})

d('GET /v1/verifications/:sessionId', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(statsRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('returns the verification by sessionId', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const dev = await createDevice(customer.id)
    const v = await createVerification(customer.id, dev.id, { confidence: 'high' })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/verifications/${v.sessionId}`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(200)
    expect((res.json() as { sessionId: string }).sessionId).toBe(v.sessionId)
  })

  it('returns 404 for a sessionId belonging to a different customer (no info leak)', async () => {
    const a = await createSandboxCustomer()
    const b = await createSandboxCustomer()
    const devB = await createDevice(b.customer.id)
    const v = await createVerification(b.customer.id, devB.id)

    const res = await app.inject({
      method: 'GET',
      url: `/v1/verifications/${v.sessionId}`,
      headers: { authorization: `Bearer ${a.sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(404)
  })

  it('returns 404 for an unknown sessionId', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/verifications/ses_does_not_exist`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(404)
  })
})
