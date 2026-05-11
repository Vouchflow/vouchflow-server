import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import crypto from 'node:crypto'
import verifyRoute from '../verify.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// The /v1/verify/:id/complete route dispatches between mobile and WebAuthn
// signature paths purely on the presence of client_data_json. Without a
// platform cross-check, an adversarial caller could submit a WebAuthn-shaped
// completion against an iOS-enrolled device (or vice versa) — the signature
// check would still reject any actual forgery, but the contract should
// surface the type mismatch explicitly.

async function makeMobileDevice(customerId: string) {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  return prisma.device.create({
    data: {
      customerId,
      deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
      publicKey: publicKeyBase64,
      keyFingerprint: crypto.createHash('sha256').update(publicKeyBase64).digest('hex'),
      platform: 'ios',
      status: 'active',
      enrolledAt: new Date(),
      isSandbox: true,
    },
  })
}

async function makeWebDevice(customerId: string) {
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  return prisma.device.create({
    data: {
      customerId,
      deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
      publicKey: publicKeyBase64,
      keyFingerprint: crypto.createHash('sha256').update(publicKeyBase64).digest('hex'),
      platform: 'web',
      credentialId: 'cred_' + crypto.randomBytes(8).toString('hex'),
      attestationFormat: 'none',
      status: 'active',
      enrolledAt: new Date(),
      isSandbox: true,
    },
  })
}

d('POST /v1/verify/:id/complete — platform binding', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(verifyRoute, { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('rejects WebAuthn assertion submitted for a non-web device with platform_mismatch', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const device = await makeMobileDevice(customer.id)

    // Initiate session
    const init = await app.inject({
      method: 'POST',
      url: '/v1/verify',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: device.deviceToken, context: 'login' },
    })
    const { session_id } = init.json() as { session_id: string }

    // Submit a WebAuthn-shaped completion against the iOS device
    const res = await app.inject({
      method: 'POST',
      url: `/v1/verify/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: device.deviceToken,
        signed_challenge: 'AAAA',
        biometric_used: true,
        client_data_json: 'AAAA',
        authenticator_data: 'AAAA',
        credential_id: 'AAAA',
      },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('platform_mismatch')
  })

  it('rejects mobile-format completion submitted for a web device', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const device = await makeWebDevice(customer.id)

    const init = await app.inject({
      method: 'POST',
      url: '/v1/verify',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: device.deviceToken, context: 'login' },
    })
    const { session_id } = init.json() as { session_id: string }

    // No client_data_json → mobile path. Against a web device → reject.
    const res = await app.inject({
      method: 'POST',
      url: `/v1/verify/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: device.deviceToken,
        signed_challenge: 'AAAA',
        biometric_used: true,
      },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('platform_mismatch')
  })
})
