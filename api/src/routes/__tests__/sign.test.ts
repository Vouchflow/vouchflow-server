import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import crypto from 'node:crypto'
import { jwtVerify, importJWK } from 'jose'
import signRoute from '../sign.js'
import jwksRoute from '../jwks.js'
import { prisma } from '../../lib/prisma.js'
import { clearSigningKeyCache } from '../../services/signingKeys.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// ── Helpers ────────────────────────────────────────────────────────────────

const RP_ID = 'test.local'

/** Generate an EC P-256 keypair, mint a Web SDK device row, return the raw
 *  keys + a function that produces a WebAuthn assertion for a given challenge. */
async function makeWebDevice(customerId: string) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64')

  const credentialIdBytes = crypto.randomBytes(32)
  const credentialId = base64url(credentialIdBytes)
  const deviceToken = `dvt_${crypto.randomBytes(8).toString('hex')}`

  await prisma.device.create({
    data: {
      customerId,
      deviceToken,
      publicKey: publicKeyBase64,
      keyFingerprint: crypto.createHash('sha256').update(publicKeyBase64).digest('hex'),
      platform: 'web',
      credentialId,
      attestationFormat: 'none',
      attestationVerified: false,
      confidenceCeiling: 'high',  // override the default ceiling so high-min sign works in tests
      status: 'active',
      enrolledAt: new Date(),
      isSandbox: true,
    },
  })

  /** Build a WebAuthn assertion (clientDataJSON + authenticatorData + signature)
   *  for the given challenge, using `webauthn.get` type and the canonical
   *  signedData = authenticatorData || SHA-256(clientDataJSON). */
  function assertionFor(challengeBase64: string, opts: {
    type?: string
    origin?: string
    flags?: number
    rpId?: string
  } = {}) {
    const type = opts.type ?? 'webauthn.get'
    const origin = opts.origin ?? `https://${RP_ID}`
    const flags = opts.flags ?? 0x05  // UV (0x04) + UP (0x01)
    const rpId = opts.rpId ?? RP_ID

    const clientData = {
      type,
      challenge: base64ToBase64url(challengeBase64),
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
      credential_id: credentialId,
    }
  }

  return { deviceToken, credentialId, publicKeyBase64, assertionFor }
}

function base64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}
function base64ToBase64url(b64: string): string {
  return b64.replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

// ── Tests ───────────────────────────────────────────────────────────────────

d('POST /v1/sign — initiate', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(signRoute, { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => {
    await cleanDb()
    // The encryption key may rotate between test runs; clear stale rows + cache.
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "signing_keys" RESTART IDENTITY CASCADE')
    clearSigningKeyCache()
  })

  it('returns session_id, challenge, expires_at, payload_sha256', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken } = await makeWebDevice(customer.id)
    const payload = '{"a":1,"b":2}'

    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'mandate_signing', canonicalized_payload: payload },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as { session_id: string; challenge: string; payload_sha256: string }
    expect(body.session_id).toMatch(/^ses_/)
    expect(body.challenge).toBeTruthy()
    expect(body.payload_sha256).toBe(crypto.createHash('sha256').update(payload).digest('hex'))
  })

  it('404 for unknown device_token', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: 'dvt_nope', context: 'x', canonicalized_payload: '{}' },
    })
    expect(res.statusCode).toBe(404)
  })

  it('422 for non-web platform device', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const device = await prisma.device.create({
      data: {
        customerId: customer.id,
        deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
        publicKey: crypto.randomBytes(64).toString('base64'),
        keyFingerprint: crypto.randomBytes(32).toString('hex'),
        platform: 'ios',
        status: 'active',
        isSandbox: true,
      },
    })
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: device.deviceToken, context: 'x', canonicalized_payload: '{}' },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('unsupported_platform')
  })

  it('422 when minimum_confidence exceeds device ceiling', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const device = await prisma.device.create({
      data: {
        customerId: customer.id,
        deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
        publicKey: crypto.randomBytes(64).toString('base64'),
        keyFingerprint: crypto.randomBytes(32).toString('hex'),
        platform: 'web',
        confidenceCeiling: 'medium',
        status: 'active',
        isSandbox: true,
      },
    })
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: device.deviceToken,
        context: 'x',
        canonicalized_payload: '{}',
        minimum_confidence: 'high',
      },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('verification_impossible')
  })
})

d('POST /v1/sign/:session_id/complete — happy path', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(signRoute, { prefix: '/v1' })
      await fastify.register(jwksRoute, { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => {
    await cleanDb()
    // The encryption key may rotate between test runs; clear stale rows + cache.
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "signing_keys" RESTART IDENTITY CASCADE')
    clearSigningKeyCache()
  })

  it('completes and returns a verifiable JWS assertion', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, assertionFor } = await makeWebDevice(customer.id)
    const payload = '{"id":"mand_123","scope":"send"}'

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'mandate_signing', canonicalized_payload: payload },
    })
    const { session_id, challenge, payload_sha256 } = init.json() as {
      session_id: string; challenge: string; payload_sha256: string
    }

    const assertion = assertionFor(challenge)

    const complete = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, ...assertion },
    })
    expect(complete.statusCode).toBe(200)
    const body = complete.json() as {
      verified: boolean
      confidence: string
      device_token: string
      signing_device_id: string
      signed_at: string
      assertion: string
      session_id: string
    }
    expect(body.verified).toBe(true)
    expect(body.signing_device_id).toMatch(/^sdv_/)
    expect(body.session_id).toBe(session_id)
    expect(body.assertion.split('.').length).toBe(3)  // JWS compact

    // Verify JWS against JWKS
    const jwks = await app.inject({ method: 'GET', url: '/v1/.well-known/jwks.json' })
    expect(jwks.statusCode).toBe(200)
    const { keys } = jwks.json() as { keys: any[] }
    expect(keys.length).toBeGreaterThan(0)

    // Decode JWS header to find kid, then verify
    const headerB64 = body.assertion.split('.')[0]
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'))
    const matchingJwk = keys.find((k) => k.kid === header.kid)
    expect(matchingJwk).toBeTruthy()
    const verifyKey = await importJWK(matchingJwk, 'EdDSA')
    const { payload: claims } = await jwtVerify(body.assertion, verifyKey, {
      issuer: 'https://vouchflow.dev',
      audience: customer.id,
    })
    expect(claims.payload_sha256).toBe(payload_sha256)
    expect(claims.context).toBe('mandate_signing')
    expect(claims.session_id).toBe(session_id)
    expect(claims.device_token).toBe(deviceToken)
  })

  it('rejects with 422 when WebAuthn challenge is tampered', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, assertionFor } = await makeWebDevice(customer.id)

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: '{}' },
    })
    const { session_id } = init.json() as { session_id: string }

    // Build an assertion for a *different* challenge — assertion should fail
    const wrongChallenge = crypto.randomBytes(32).toString('base64')
    const assertion = assertionFor(wrongChallenge)

    const res = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, ...assertion },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('invalid_signature')
  })

  it('rejects double-completion with challenge_already_consumed', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, assertionFor } = await makeWebDevice(customer.id)

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: '{}' },
    })
    const { session_id, challenge } = init.json() as { session_id: string; challenge: string }
    const assertion = assertionFor(challenge)

    const first = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, ...assertion },
    })
    expect(first.statusCode).toBe(200)

    const second = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, ...assertion },
    })
    expect([409, 422]).toContain(second.statusCode)  // either consumed or invalid_session_state
  })

  it('idempotency_key replay returns the same session_id', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken } = await makeWebDevice(customer.id)

    const body = {
      device_token: deviceToken,
      context: 'replay_test',
      canonicalized_payload: '{"x":1}',
      idempotency_key: `ek_${crypto.randomBytes(8).toString('hex')}`,
    }
    const first = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: body,
    })
    const second = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: body,
    })
    expect(first.statusCode).toBe(200)
    expect(second.statusCode).toBe(200)
    expect(first.json().session_id).toBe(second.json().session_id)
    void customer
  })

  it('404 on missing session', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign/ses_doesnotexist/complete',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: 'dvt_x',
        signed_challenge: 'aa',
        client_data_json: 'aa',
        authenticator_data: 'aa',
        credential_id: 'aa',
      },
    })
    expect(res.statusCode).toBe(404)
  })
})

d('GET /v1/.well-known/jwks.json', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(jwksRoute, { prefix: '/v1' })
    })
  })
  beforeEach(async () => {
    // Ensure at least one signing key exists for the JWKS test.
    const { getActiveSigningKey } = await import('../../services/signingKeys.js')
    await getActiveSigningKey()
  })
  afterAll(async () => app.close())

  it('returns JWKS shape', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/.well-known/jwks.json' })
    expect(res.statusCode).toBe(200)
    expect(res.headers['cache-control']).toContain('max-age=3600')
    const body = res.json() as { keys: Array<{ kty: string; kid: string; use: string; alg: string }> }
    expect(body.keys.length).toBeGreaterThan(0)
    for (const k of body.keys) {
      expect(k.use).toBe('sig')
      expect(k.alg).toBe('EdDSA')
      expect(k.kty).toBe('OKP')
      expect(k.kid).toBeTruthy()
    }
  })
})
