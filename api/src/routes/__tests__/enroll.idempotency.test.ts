import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import crypto from 'node:crypto'
import enrollRoute from '../enroll.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// §7 Idempotency contract: two POST /v1/enroll calls with the same
// idempotency_key within a 24h window must return the same response.
// Replay protection — a network retry, an offline-then-online retry,
// a stuck queue handler — must not mint a second device token.
//
// Storage is two-tier: Redis cache for fast-path, DB fallback when
// Redis evicts. Both are exercised by the tests below.

/** SubjectPublicKeyInfo of an EC P-256 public key, base64. The enroll route
 *  doesn't validate the key (the verify route does), but it does hash it
 *  for the keyFingerprint column, so any unique value works. */
function freshPublicKey(): string {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
}

d('POST /v1/enroll — idempotency replay protection', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(enrollRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('returns the SAME response for two requests with the same idempotency_key', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const idempotencyKey = `ik_${crypto.randomBytes(8).toString('hex')}`

    const first = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: idempotencyKey,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: freshPublicKey(),
      },
    })
    expect(first.statusCode).toBe(200)
    const firstBody = first.json() as { device_token: string }

    // Second call with same idempotency_key but a *different* public_key —
    // the response should still be the original one, proving the route
    // short-circuited on idempotency before doing anything else.
    const second = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: idempotencyKey,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: freshPublicKey(),  // DIFFERENT key
      },
    })
    expect(second.statusCode).toBe(200)
    const secondBody = second.json() as { device_token: string }

    expect(secondBody.device_token).toBe(firstBody.device_token)
    expect(secondBody).toEqual(firstBody)

    // And only ONE device row was created — replay didn't mint a second
    // device under the new public key.
    const deviceCount = await prisma.device.count()
    expect(deviceCount).toBe(1)
  })

  it('different idempotency_keys → different device tokens', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()

    const first = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: `ik_${crypto.randomBytes(8).toString('hex')}`,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: freshPublicKey(),
      },
    })
    const second = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: `ik_${crypto.randomBytes(8).toString('hex')}`,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: freshPublicKey(),
      },
    })
    const a = first.json() as { device_token: string }
    const b = second.json() as { device_token: string }
    expect(a.device_token).not.toBe(b.device_token)
  })

  it('falls back to DB when Redis cache miss (record present in idempotency_records table)', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const idempotencyKey = `ik_${crypto.randomBytes(8).toString('hex')}`

    const first = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: idempotencyKey,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: freshPublicKey(),
      },
    })
    const firstBody = first.json() as { device_token: string }

    // Simulate Redis eviction.
    const { redis } = await import('../../lib/redis.js')
    await redis.del(`idempotency:${idempotencyKey}`)

    // Replay — must still return the same body (DB fallback hit).
    const second = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: idempotencyKey,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: freshPublicKey(),
      },
    })
    expect(second.statusCode).toBe(200)
    const secondBody = second.json() as { device_token: string }
    expect(secondBody.device_token).toBe(firstBody.device_token)
  })

  it('treats expired DB record as not-found (mints a fresh device token)', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const idempotencyKey = `ik_${crypto.randomBytes(8).toString('hex')}`

    const first = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: idempotencyKey,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: freshPublicKey(),
      },
    })
    const firstBody = first.json() as { device_token: string }

    // Force-expire: rewind the DB record's expiresAt and drop the Redis cache.
    await prisma.idempotencyRecord.update({
      where: { key: idempotencyKey },
      data:  { expiresAt: new Date(Date.now() - 1000) },
    })
    const { redis } = await import('../../lib/redis.js')
    await redis.del(`idempotency:${idempotencyKey}`)

    const second = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: idempotencyKey,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: freshPublicKey(),
      },
    })
    expect(second.statusCode).toBe(200)
    const secondBody = second.json() as { device_token: string }
    // Different token because the original idempotency window expired.
    expect(secondBody.device_token).not.toBe(firstBody.device_token)
  })

  it('rejects a public_key already registered to a DIFFERENT device token (409)', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const sharedPublicKey = freshPublicKey()

    // First enrollment with idem key A — creates the device.
    const first = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: `ik_${crypto.randomBytes(8).toString('hex')}`,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: sharedPublicKey,
      },
    })
    expect(first.statusCode).toBe(200)

    // Second enrollment with a DIFFERENT idem key but the same public_key,
    // and no device_token in the body — that's the conflict.
    const second = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        idempotency_key: `ik_${crypto.randomBytes(8).toString('hex')}`,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: sharedPublicKey,
      },
    })
    expect(second.statusCode).toBe(409)
    expect(second.json()).toMatchObject({
      error: { code: 'public_key_already_registered' },
    })
  })
})
