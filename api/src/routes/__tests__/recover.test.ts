import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { FastifyInstance } from 'fastify'
import crypto from 'node:crypto'
import recoverRoute from '../recover.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip
const RP_ID = 'test.local'

d('device recovery', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(recoverRoute, { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  async function fixture() {
    const { customer, app: enrolledApp, sandboxWriteKey } = await createSandboxCustomer()
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
    const credentialId = crypto.randomBytes(32).toString('base64url')
    const deviceToken = `dvt_${crypto.randomBytes(8).toString('hex')}`
    const device = await prisma.device.create({
      data: {
        customerId: customer.id,
        appId: enrolledApp.id,
        deviceToken,
        publicKey: publicKeyBase64,
        keyFingerprint: crypto.createHash('sha256').update(publicKeyBase64).digest('hex'),
        platform: 'web',
        credentialId,
        status: 'active',
        enrolledAt: new Date(),
        isSandbox: true,
      },
    })

    function assertion(challenge: string, overrides: { signatureKey?: crypto.KeyObject; origin?: string; flags?: number } = {}) {
      const clientDataJSON = Buffer.from(JSON.stringify({
        type: 'webauthn.get',
        challenge: Buffer.from(challenge, 'base64').toString('base64url'),
        origin: overrides.origin ?? `https://${RP_ID}`,
        crossOrigin: false,
      }))
      const authenticatorData = Buffer.concat([
        crypto.createHash('sha256').update(RP_ID).digest(),
        Buffer.from([overrides.flags ?? 0x05]),
        Buffer.alloc(4),
      ])
      const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest()
      const signature = crypto.createSign('SHA256')
        .update(Buffer.concat([authenticatorData, clientDataHash]))
        .sign(overrides.signatureKey ?? privateKey)
      return {
        credential_id: credentialId,
        client_data_json: clientDataJSON.toString('base64'),
        authenticator_data: authenticatorData.toString('base64'),
        signed_challenge: signature.toString('base64'),
      }
    }

    async function initiate(key = sandboxWriteKey) {
      const response = await app.inject({
        method: 'POST', url: '/v1/device/recover/initiate',
        headers: { authorization: `Bearer ${key}` }, payload: {},
      })
      expect(response.statusCode).toBe(200)
      return response.json() as { session_id: string; challenge: string; expires_at: string }
    }

    async function complete(sessionId: string, challenge: string, key = sandboxWriteKey, overrides = {}) {
      return app.inject({
        method: 'POST', url: '/v1/device/recover/complete',
        headers: { authorization: `Bearer ${key}` },
        payload: { session_id: sessionId, ...assertion(challenge), ...overrides },
      })
    }

    return { customer, enrolledApp, sandboxWriteKey, device, credentialId, assertion, initiate, complete }
  }

  it('returns the existing device token and credential ID for a valid assertion', async () => {
    const { device, credentialId, initiate, complete } = await fixture()
    const before = device.lastSeen
    const session = await initiate()
    expect(Buffer.from(session.challenge, 'base64')).toHaveLength(32)
    expect(new Date(session.expires_at).getTime()).toBeGreaterThan(Date.now())

    const response = await complete(session.session_id, session.challenge)
    expect(response.statusCode).toBe(200)
    expect(response.json()).toEqual({ device_token: device.deviceToken, credential_id: credentialId })
    const recovered = await prisma.device.findUniqueOrThrow({ where: { id: device.id } })
    expect(recovered.lastSeen!.getTime()).toBeGreaterThan(before?.getTime() ?? 0)
    const verification = await prisma.verification.findUniqueOrThrow({ where: { sessionId: session.session_id } })
    expect(verification.state).toBe('COMPLETED')
    expect(verification.challengeConsumed).toBe(true)
    expect(verification.deviceId).toBe(device.id)
    expect(verification.completionResponse).toBeNull()
  })

  it('returns 404 for another app’s or an unknown credential', async () => {
    const { customer, initiate, complete } = await fixture()
    const otherKey = `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`
    await prisma.app.create({
      data: {
        customerId: customer.id,
        name: 'Other App', slug: 'other',
        sandboxWriteKey: otherKey,
        sandboxReadKey: `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`,
      },
    })

    const otherSession = await initiate(otherKey)
    const crossApp = await complete(otherSession.session_id, otherSession.challenge, otherKey)
    expect(crossApp.statusCode).toBe(404)
    expect(crossApp.json().error.code).toBe('device_not_found')

    const session = await initiate()
    const unknown = await complete(session.session_id, session.challenge, undefined, {
      credential_id: crypto.randomBytes(32).toString('base64url'),
    })
    expect(unknown.statusCode).toBe(404)
    expect(unknown.json().error.code).toBe('device_not_found')
  })

  it('rejects a signature from another key', async () => {
    const { initiate, complete } = await fixture()
    const session = await initiate()
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const response = await complete(session.session_id, session.challenge, undefined, {
      signed_challenge: crypto.createSign('SHA256').update('wrong').sign(privateKey).toString('base64'),
    })
    expect(response.statusCode).toBe(422)
    expect(response.json().error.code).toBe('invalid_signature')
  })

  it('returns 409 when a completed session is reused and 410 when it expires', async () => {
    const { initiate, complete } = await fixture()
    const session = await initiate()
    expect((await complete(session.session_id, session.challenge)).statusCode).toBe(200)
    const reused = await complete(session.session_id, session.challenge)
    expect(reused.statusCode).toBe(409)

    const expiredSession = await initiate()
    await prisma.verification.update({
      where: { sessionId: expiredSession.session_id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    })
    const expired = await complete(expiredSession.session_id, expiredSession.challenge)
    expect(expired.statusCode).toBe(410)
    expect(expired.json().error.code).toBe('session_expired')
  })
})
