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

    // (Previously this test deleted a Redis cache entry to force a DB
    // fallback. The Redis cache layer is gone — every lookup is Postgres —
    // so the test reduces to "second call with same key returns the same
    // body". Kept as a regression guard against accidentally inserting a
    // new layer that would short-circuit the DB read.)
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

    // Force-expire: rewind the DB record's expiresAt. The Postgres lookup
    // honours expiresAt, so we don't need anything else (used to also drop
    // a Redis cache entry; the cache layer is gone).
    await prisma.idempotencyRecord.update({
      where: { key: idempotencyKey },
      data:  { expiresAt: new Date(Date.now() - 1000) },
    })

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

  it('re-tokens a public_key re-registered under the SAME tenant (200, same device_token)', async () => {
    // Same customer + app re-registering the same public_key with a new idem
    // key and no device_token is a legitimate re-token (e.g. an SDK reset()
    // that wiped the local token but the hardware key survived). The server
    // returns the EXISTING device_token rather than 409. See enroll.ts and
    // issue #6 (the older form blanket-409'd and made sandbox→prod device
    // migration unrecoverable for integrators).
    const { sandboxWriteKey } = await createSandboxCustomer()
    const sharedPublicKey = freshPublicKey()

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
    const firstToken = (first.json() as { device_token: string }).device_token

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
    expect(second.statusCode).toBe(200)
    // Re-token: same device, same token — not a second device minted.
    expect((second.json() as { device_token: string }).device_token).toBe(firstToken)
  })

  it('rejects a public_key already registered under a DIFFERENT tenant (409)', async () => {
    // Cross-tenant collision (someone cloning a key under another customer) is
    // still a hard 409 — only same-tenant re-registration re-tokens.
    const tenantA = await createSandboxCustomer()
    const tenantB = await createSandboxCustomer()
    const sharedPublicKey = freshPublicKey()

    const first = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${tenantA.sandboxWriteKey}` },
      payload: {
        idempotency_key: `ik_${crypto.randomBytes(8).toString('hex')}`,
        platform: 'android',
        reason: 'fresh_enrollment',
        public_key: sharedPublicKey,
      },
    })
    expect(first.statusCode).toBe(200)

    const second = await app.inject({
      method: 'POST',
      url: '/v1/enroll',
      headers: { authorization: `Bearer ${tenantB.sandboxWriteKey}` },
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
