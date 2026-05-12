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
  // Apps refactor: device rows need appId. Look up the customer's default app.
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
      confidenceCeiling: 'high',  // override the default ceiling so high-min sign works in tests
      status: 'active',
      enrolledAt: new Date(),
      isSandbox: true,
    },
  })

  /** Build a WebAuthn assertion bundle for the new RFC wire format:
   *  the SDK sets clientData.challenge = base64url(SHA-256(canonical || challenge)).
   *  The test takes the same canonical_payload and raw server challenge that
   *  POST /v1/sign returned and reconstructs that hash. */
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
      credential_id: credentialId,
    }
  }

  return { deviceToken, credentialId, publicKeyBase64, assertionFor }
}

/** Build a mobile (iOS or Android) sign device. The signature is a raw
 *  ECDSA-P256 over `canonical || challenge` — no clientDataJSON wrapping.
 *  Both platforms produce identical bytes for this signature; the only
 *  difference at the wire level is the optional app_attest_assertion field. */
async function makeMobileSignDevice(
  customerId: string,
  platform: 'ios' | 'android',
  opts: { ageDays?: number } = {},
) {
  // Apps refactor: device rows need appId.
  const app = await prisma.app.findFirst({
    where: { customerId, archivedAt: null },
    orderBy: { createdAt: 'asc' },
  })
  if (!app) throw new Error(`makeMobileSignDevice: customer ${customerId} has no app`)

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64')
  const deviceToken = `dvt_${crypto.randomBytes(8).toString('hex')}`
  // computeConfidence requires deviceAgeDays > 30 for `high`. Default to a
  // 60-day-old device so tests asserting `high` aren't capped by age.
  const ageDays = opts.ageDays ?? 60
  const enrolledAt = new Date(Date.now() - ageDays * 24 * 60 * 60 * 1000)

  await prisma.device.create({
    data: {
      customerId,
      appId: app.id,
      deviceToken,
      publicKey: publicKeyBase64,
      keyFingerprint: crypto.createHash('sha256').update(publicKeyBase64).digest('hex'),
      platform,
      attestationVerified: true,  // sandbox treats attestation as verified
      confidenceCeiling: 'high',
      status: 'active',
      enrolledAt,
      isSandbox: true,
    },
  })

  function signFor(opts: { canonicalizedPayload: string; challengeBase64: string }) {
    const canonicalBytes = Buffer.from(opts.canonicalizedPayload, 'utf8')
    const challengeBytes = Buffer.from(opts.challengeBase64, 'base64')
    const signingInput = Buffer.concat([canonicalBytes, challengeBytes])
    const signature = crypto.createSign('SHA256').update(signingInput).sign(privateKey)
    return signature.toString('base64')
  }

  return { deviceToken, publicKeyBase64, signFor }
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

  it('iOS device may initiate sign (Phase 2)', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken } = await makeMobileSignDevice(customer.id, 'ios')
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: '{}' },
    })
    expect(res.statusCode).toBe(200)
    void customer
  })

  it('Android device may initiate sign (Phase 2)', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken } = await makeMobileSignDevice(customer.id, 'android')
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: '{}' },
    })
    expect(res.statusCode).toBe(200)
    void customer
  })

  it('422 for an exotic platform device', async () => {
    const { customer, app: appRow, sandboxWriteKey } = await createSandboxCustomer()
    const device = await prisma.device.create({
      data: {
        customerId: customer.id,
        appId: appRow.id,
        deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
        publicKey: crypto.randomBytes(64).toString('base64'),
        keyFingerprint: crypto.randomBytes(32).toString('hex'),
        platform: 'unknown',
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
    const { customer, app: appRow, sandboxWriteKey } = await createSandboxCustomer()
    const device = await prisma.device.create({
      data: {
        customerId: customer.id,
        appId: appRow.id,
        deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
        publicKey: crypto.randomBytes(64).toString('base64'),
        keyFingerprint: crypto.randomBytes(32).toString('hex'),
        platform: 'web',
        credentialId: crypto.randomBytes(16).toString('base64url'), // Issue #4: web devices need credentialId
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
      await fastify.register(jwksRoute)  // No prefix for /.well-known/jwks.json
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

    const assertion = assertionFor({ canonicalizedPayload: payload, challengeBase64: challenge })

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
      platform: string
    }
    expect(body.verified).toBe(true)
    expect(body.signing_device_id).toMatch(/^sdv_/)
    expect(body.session_id).toBe(session_id)
    expect(body.platform).toBe('web')
    expect(body.assertion.split('.').length).toBe(3)  // JWS compact

    // Verify JWS against JWKS
    const jwks = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })
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
    expect(claims.platform).toBe('web')
  })

  it('rejects with 422 when WebAuthn challenge is tampered', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, assertionFor } = await makeWebDevice(customer.id)
    const payload = '{}'

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: payload },
    })
    const { session_id } = init.json() as { session_id: string }

    // Build an assertion bound to a *different* challenge — assertion should fail
    const wrongChallenge = crypto.randomBytes(32).toString('base64')
    const assertion = assertionFor({
      canonicalizedPayload: payload,
      challengeBase64: wrongChallenge,
    })

    const res = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, ...assertion },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('invalid_signature')
  })

  it('rejects when canonical payload changed between init and assertion build (payload swap)', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, assertionFor } = await makeWebDevice(customer.id)
    const initiatedPayload = '{"id":"mand_real","amount":10}'

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: initiatedPayload },
    })
    const { session_id, challenge } = init.json() as { session_id: string; challenge: string }

    // Attacker tries to reuse the challenge with a different payload —
    // the assertion's WebAuthn challenge encodes the swapped payload's hash,
    // which won't match what the server expects when reconstructed.
    const swappedPayload = '{"id":"mand_real","amount":1000000}'
    const assertion = assertionFor({
      canonicalizedPayload: swappedPayload,
      challengeBase64: challenge,
    })

    const res = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, ...assertion },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('invalid_signature')
  })

  it('double-completion returns cached response (idempotent, Issue #2)', async () => {
    // After the idempotency fix, calling /complete twice on the same session
    // returns the original response (200) instead of failing with 409.
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, assertionFor } = await makeWebDevice(customer.id)
    const payload = '{}'

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: payload },
    })
    const { session_id, challenge } = init.json() as { session_id: string; challenge: string }
    const assertion = assertionFor({ canonicalizedPayload: payload, challengeBase64: challenge })

    const first = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, ...assertion },
    })
    expect(first.statusCode).toBe(200)
    const firstBody = first.json() as any
    expect(firstBody.verified).toBe(true)
    expect(firstBody.assertion).toBeTruthy()

    // Second completion should return the same response (idempotent)
    const second = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, ...assertion },
    })
    expect(second.statusCode).toBe(200)  // idempotent - returns cached response
    const secondBody = second.json() as any
    expect(secondBody.verified).toBe(true)
    expect(secondBody.assertion).toBe(firstBody.assertion)  // same assertion
    expect(secondBody.signing_device_id).toBe(firstBody.signing_device_id)
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

d('POST /v1/sign/:session_id/complete — mobile', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(signRoute, { prefix: '/v1' })
      await fastify.register(jwksRoute)  // No prefix for /.well-known/jwks.json
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => {
    await cleanDb()
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "signing_keys" RESTART IDENTITY CASCADE')
    clearSigningKeyCache()
  })

  it('iOS: completes with raw SE signature over canonical || challenge', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, signFor } = await makeMobileSignDevice(customer.id, 'ios')
    const payload = '{"id":"mand_ios","ok":true}'

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        context: 'mandate_signing',
        canonicalized_payload: payload,
        minimum_confidence: 'medium',  // no app_attest_assertion → cap medium
      },
    })
    const { session_id, challenge } = init.json() as { session_id: string; challenge: string }

    const signature = signFor({ canonicalizedPayload: payload, challengeBase64: challenge })

    const complete = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, signed_challenge: signature },
    })
    expect(complete.statusCode).toBe(200)
    const body = complete.json() as { confidence: string; platform: string; assertion: string }
    expect(body.platform).toBe('ios')
    expect(body.confidence).toBe('medium')  // capped without app_attest_assertion
    expect(body.assertion.split('.').length).toBe(3)
  })

  it('iOS: minimum_confidence=high without app_attest_assertion still ships, capped to medium', async () => {
    // Server enforces minimum_confidence at INITIATE against the device ceiling,
    // not against the runtime confidence — so a high-ceiling iOS device passes
    // the gate. The runtime confidence then caps to medium because no
    // app_attest_assertion was supplied. This documents the behaviour.
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, signFor } = await makeMobileSignDevice(customer.id, 'ios')
    const payload = '{"v":1}'

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        context: 'x',
        canonicalized_payload: payload,
        minimum_confidence: 'high',
      },
    })
    expect(init.statusCode).toBe(200)
    const { session_id, challenge } = init.json() as { session_id: string; challenge: string }
    const signature = signFor({ canonicalizedPayload: payload, challengeBase64: challenge })

    const complete = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, signed_challenge: signature },
    })
    expect(complete.statusCode).toBe(200)
    expect(complete.json().confidence).toBe('medium')
    void customer
  })

  it('iOS: with valid app_attest_assertion confidence reaches high', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, signFor } = await makeMobileSignDevice(customer.id, 'ios')
    const payload = '{"v":1}'

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: payload },
    })
    const { session_id, challenge } = init.json() as { session_id: string; challenge: string }
    const signature = signFor({ canonicalizedPayload: payload, challengeBase64: challenge })

    // Craft a well-formed-enough App Attest assertion CBOR. v1 server-side
    // verification accepts any well-formed assertion (per the comment in
    // routes/sign.ts — full Apple-root verification is a v2 hardening).
    const fakeAuthenticatorData = Buffer.alloc(37, 0xaa)
    const fakeSignature = Buffer.alloc(64, 0xbb)
    const assertionCbor = encodeAppAttestAssertion(fakeAuthenticatorData, fakeSignature)

    const complete = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        signed_challenge: signature,
        app_attest_assertion: assertionCbor.toString('base64'),
      },
    })
    expect(complete.statusCode).toBe(200)
    expect(complete.json().confidence).toBe('high')
    void customer
  })

  it('Android: completes with raw Keystore signature, confidence inherits from ceiling', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, signFor } = await makeMobileSignDevice(customer.id, 'android')
    const payload = '{"id":"mand_android"}'

    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: payload },
    })
    const { session_id, challenge } = init.json() as { session_id: string; challenge: string }
    const signature = signFor({ canonicalizedPayload: payload, challengeBase64: challenge })

    const complete = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, signed_challenge: signature },
    })
    expect(complete.statusCode).toBe(200)
    const body = complete.json() as { platform: string; confidence: string }
    expect(body.platform).toBe('android')
    expect(body.confidence).toBe('high')  // Android keeps its ceiling
    void customer
  })

  it('mobile: payload swap (sign different bytes than session stored) is rejected', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken, signFor } = await makeMobileSignDevice(customer.id, 'android')
    const initiated = '{"id":"mand","amount":10}'
    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: initiated },
    })
    const { session_id, challenge } = init.json() as { session_id: string; challenge: string }

    // Sign over different bytes than the session stored — signature verifies
    // against canonical || challenge, server reconstructs canonical from the
    // session record, hashes don't match.
    const signature = signFor({
      canonicalizedPayload: '{"id":"mand","amount":1000000}',
      challengeBase64: challenge,
    })

    const res = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, signed_challenge: signature },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('invalid_signature')
    void customer
  })

  it('platform_mismatch: web device receives mobile-format completion', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken } = await makeWebDevice(customer.id)
    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: '{}' },
    })
    const { session_id } = init.json() as { session_id: string }
    const res = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, signed_challenge: 'AAAA' },  // mobile-style
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('platform_mismatch')
    void customer
  })

  it('platform_mismatch: mobile device receives WebAuthn-format completion', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const { deviceToken } = await makeMobileSignDevice(customer.id, 'ios')
    const init = await app.inject({
      method: 'POST',
      url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: deviceToken, context: 'x', canonicalized_payload: '{}' },
    })
    const { session_id } = init.json() as { session_id: string }
    const res = await app.inject({
      method: 'POST',
      url: `/v1/sign/${session_id}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: deviceToken,
        signed_challenge: 'AAAA',
        client_data_json: 'AAAA',
        authenticator_data: 'AAAA',
        credential_id: 'AAAA',
      },
    })
    expect(res.statusCode).toBe(422)
    expect(res.json().error.code).toBe('platform_mismatch')
    void customer
  })
})

// Build a minimal CBOR map { authenticatorData: bytes, signature: bytes }
// matching the shape DCAppAttestService.generateAssertion produces.
function encodeAppAttestAssertion(authData: Buffer, signature: Buffer): Buffer {
  const cbor: number[] = []
  cbor.push(0xa2)  // map with 2 entries
  // "authenticatorData" key
  cbor.push(0x71)  // text string length 17
  cbor.push(...Buffer.from('authenticatorData', 'utf8'))
  // byte string value
  pushByteString(cbor, authData)
  // "signature" key
  cbor.push(0x69)  // text string length 9
  cbor.push(...Buffer.from('signature', 'utf8'))
  pushByteString(cbor, signature)
  return Buffer.from(cbor)
}

function pushByteString(buf: number[], bytes: Buffer): void {
  if (bytes.length < 24) {
    buf.push(0x40 | bytes.length)
  } else if (bytes.length < 256) {
    buf.push(0x58, bytes.length)
  } else {
    buf.push(0x59, (bytes.length >> 8) & 0xff, bytes.length & 0xff)
  }
  for (const b of bytes) buf.push(b)
}

d('GET /.well-known/jwks.json', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(jwksRoute)  // No prefix for /.well-known/jwks.json
    })
  })
  beforeEach(async () => {
    // Ensure at least one signing key exists for the JWKS test.
    const { getActiveSigningKey } = await import('../../services/signingKeys.js')
    await getActiveSigningKey()
  })
  afterAll(async () => app.close())

  it('returns JWKS shape', async () => {
    const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })
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
