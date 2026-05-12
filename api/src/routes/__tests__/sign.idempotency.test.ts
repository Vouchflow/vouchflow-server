// Test for Issue #2: POST /v1/sign/:session_id/complete idempotency
//
// When /complete succeeds server-side but the response is lost (network blip,
// HMR reload), a retry should return the original response (200) instead of
// failing with "Session is in state COMPLETED, expected INITIATED" (409).

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import crypto from 'node:crypto'
import signRoute from '../sign.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// ── Helpers ────────────────────────────────────────────────────────────────

const RP_ID = 'test.local'

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function base64ToBase64url(b64: string): string {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Generate an EC P-256 keypair, mint a Web SDK device row, return the raw
 *  keys + a function that produces a WebAuthn assertion for a given challenge. */
async function makeWebDevice(customerId: string) {
  const app = await prisma.app.findFirst({
    where: { customerId, archivedAt: null },
    orderBy: { createdAt: 'asc' },
  })
  if (!app) throw new Error(`makeWebDevice: customer ${customerId} has no app`)

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64')

  const credentialIdBytes = crypto.randomBytes(32)
  const credentialId = base64url(credentialIdBytes)
  const deviceToken = `dvt_${crypto.randomBytes(8).toString('hex')}`

  await prisma.device.create({
    data: {
      customerId,
      appId: app.id,
      deviceToken,
      publicKey: publicKeyBase64,
      keyFingerprint: crypto.createHash('sha256').update(publicKeyBase64).digest('hex'),
      platform: 'web',
      credentialId,
      attestationFormat: 'none',
      attestationVerified: false,
      confidenceCeiling: 'high',
      status: 'active',
      enrolledAt: new Date(),
      isSandbox: true,
    },
  })

  function assertionFor(opts: {
    canonicalizedPayload: string
    challengeBase64: string
    type?: string
    origin?: string
    flags?: number
    rpId?: string
  }) {
    const type = opts.type ?? 'webauthn.get'
    const origin = opts.origin ?? `https://${RP_ID}`
    const flags = opts.flags ?? 0x05  // UV (0x04) + UP (0x01)
    const rpId = opts.rpId ?? RP_ID

    const canonicalBytes = Buffer.from(opts.canonicalizedPayload, 'utf8')
    const challengeBytes = Buffer.from(opts.challengeBase64, 'base64')
    const signingInputHash = crypto
      .createHash('sha256')
      .update(Buffer.concat([canonicalBytes, challengeBytes]))
      .digest()

    const clientData = {
      type,
      challenge: base64ToBase64url(signingInputHash.toString('base64')),
      origin,
      crossOrigin: false,
    }
    const clientDataJSON = Buffer.from(JSON.stringify(clientData), 'utf8')
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest()

    const rpIdHash = crypto.createHash('sha256').update(rpId, 'utf8').digest()
    const signCount = Buffer.alloc(4)
    signCount.writeUInt32BE(1, 0)
    const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([flags]), signCount])

    const signedData = Buffer.concat([authenticatorData, clientDataHash])
    const signature = crypto.createSign('SHA256').update(signedData).sign(privateKey)

    return {
      client_data_json: clientDataJSON.toString('base64'),
      authenticator_data: authenticatorData.toString('base64'),
      signed_challenge: signature.toString('base64'),
    }
  }

  return { deviceToken, assertionFor }
}

// ── Tests ──────────────────────────────────────────────────────────────────

d('POST /v1/sign/:session_id/complete idempotency (Issue #2)', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(signRoute, { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('returns 200 with original response when called twice on COMPLETED session', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, assertionFor } = await makeWebDevice(customer.id)
    const appId = (await prisma.app.findFirst({ where: { customerId: customer.id } }))!.id

    // Initiate sign
    const canonicalizedPayload = '{"test":"data"}'
    const initRes = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        context: 'test_ceremony',
        canonicalized_payload: canonicalizedPayload,
        minimum_confidence: 'medium',
      },
    })
    expect(initRes.statusCode).toBe(200)
    const initBody = initRes.json() as any
    const sessionId = initBody.session_id
    const challenge = initBody.challenge

    // Complete sign (first time)
    const assertion = assertionFor({ canonicalizedPayload, challengeBase64: challenge })
    const completeRes1 = await app.inject({
      method: 'POST',
      url: `/v1/sign/${sessionId}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        ...assertion,
      },
    })
    expect(completeRes1.statusCode).toBe(200)
    const body1 = completeRes1.json() as any
    expect(body1.verified).toBe(true)
    expect(body1.assertion).toBeTruthy()
    expect(body1.signing_device_id).toBeTruthy()

    // Complete sign again (simulates lost response + retry)
    const completeRes2 = await app.inject({
      method: 'POST',
      url: `/v1/sign/${sessionId}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        ...assertion,
      },
    })

    // Should return 200 with the same response
    expect(completeRes2.statusCode).toBe(200)
    const body2 = completeRes2.json() as any
    expect(body2.verified).toBe(true)
    expect(body2.assertion).toBe(body1.assertion)
    expect(body2.signing_device_id).toBe(body1.signing_device_id)
    expect(body2.signed_at).toBe(body1.signed_at)
    expect(body2.confidence).toBe(body1.confidence)
  })

  it('old behavior: before idempotency fix would return 409 invalid_session_state', async () => {
    // This test documents the old buggy behavior for comparison.
    // After the fix, calling /complete on a COMPLETED session should return
    // the cached response (200) instead of this error.
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, assertionFor } = await makeWebDevice(customer.id)

    const canonicalizedPayload = '{"test":"data"}'
    const initRes = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        context: 'test_ceremony',
        canonicalized_payload: canonicalizedPayload,
        minimum_confidence: 'medium',
      },
    })
    const initBody = initRes.json() as any
    const sessionId = initBody.session_id

    // Manually set session to COMPLETED without completionResponse (simulates old behavior)
    await prisma.verification.update({
      where: { sessionId },
      data: { state: 'COMPLETED', completedAt: new Date() },
    })

    const assertion = assertionFor({
      canonicalizedPayload,
      challengeBase64: initBody.challenge,
    })
    const completeRes = await app.inject({
      method: 'POST',
      url: `/v1/sign/${sessionId}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        ...assertion,
      },
    })

    // With the fix, this returns 409 ceremony_already_completed (no cached response)
    // This is different from the old 409 invalid_session_state error
    expect(completeRes.statusCode).toBe(409)
    const body = completeRes.json() as any
    expect(body.error.code).toBe('ceremony_already_completed')
  })
})
