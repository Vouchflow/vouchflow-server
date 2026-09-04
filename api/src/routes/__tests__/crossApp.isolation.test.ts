// Cross-app isolation: a key issued for App A cannot operate on devices
// belonging to App B, even within the same Customer. We return the same
// error code as cross-customer access (`device_not_owned` for verify/sign,
// `device_not_found` for the read endpoint) so a sibling app can't probe
// for device existence via differential errors.

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import crypto from 'node:crypto'
import enrollRoute from '../enroll.js'
import verifyRoute from '../verify.js'
import signRoute from '../sign.js'
import deviceRoute from '../device.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
  createVerification,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

d('cross-app isolation', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(enrollRoute,  { prefix: '/v1' })
      await fastify.register(verifyRoute,  { prefix: '/v1' })
      await fastify.register(signRoute,    { prefix: '/v1' })
      await fastify.register(deviceRoute,  { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  // Build: one Customer, two Apps (A and B). Device enrolled under App A.
  // Then attempt to act on the device using App B's sandbox key.
  async function setup() {
    const { customer, app: appA } = await createSandboxCustomer()
    const sandboxWriteKeyA = appA.sandboxWriteKey!
    const sandboxReadKeyA  = appA.sandboxReadKey!

    const sandboxWriteKeyB = `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`
    const sandboxReadKeyB  = `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`
    const appB = await prisma.app.create({
      data: {
        customerId: customer.id,
        name: 'B', slug: 'b',
        sandboxWriteKey: sandboxWriteKeyB,
        sandboxReadKey:  sandboxReadKeyB,
        signPayloadMinConfidence: 'high',
      },
    })

    // Mint a Device under App A directly.
    const device = await prisma.device.create({
      data: {
        customerId: customer.id,
        appId: appA.id,
        deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
        publicKey: crypto.randomBytes(64).toString('base64'),
        keyFingerprint: crypto.randomBytes(32).toString('hex'),
        platform: 'web',
        confidenceCeiling: 'high',
        attestationFormat: 'none',
        credentialId: 'cred_' + crypto.randomBytes(8).toString('hex'),
        status: 'active',
        enrolledAt: new Date(),
        isSandbox: true,
      },
    })

    return { customer, appA, appB, device, sandboxWriteKeyA, sandboxReadKeyA, sandboxWriteKeyB, sandboxReadKeyB }
  }

  it('verify with App B\'s key against App A\'s device → 403 device_not_owned', async () => {
    const { device, sandboxWriteKeyB } = await setup()
    const res = await app.inject({
      method: 'POST', url: '/v1/verify',
      headers: { authorization: `Bearer ${sandboxWriteKeyB}` },
      payload: { device_token: device.deviceToken, context: 'login' },
    })
    expect(res.statusCode).toBe(403)
    expect((res.json() as any).error.code).toBe('device_not_owned')
  })

  it('verify with App A\'s key against App A\'s device → succeeds (control)', async () => {
    const { device, sandboxWriteKeyA } = await setup()
    const res = await app.inject({
      method: 'POST', url: '/v1/verify',
      headers: { authorization: `Bearer ${sandboxWriteKeyA}` },
      payload: { device_token: device.deviceToken, context: 'login' },
    })
    expect(res.statusCode).toBe(200)
  })

  it('fallback with App B\'s key against App A\'s session → 403 without transitioning it', async () => {
    const { customer, appA, device, sandboxWriteKeyB } = await setup()
    const session = await createVerification(customer.id, device.id, {
      appId: appA.id,
      state: 'INITIATED',
      completedAt: null,
    })

    const res = await app.inject({
      method: 'POST',
      url: `/v1/verify/${session.sessionId}/fallback`,
      headers: { authorization: `Bearer ${sandboxWriteKeyB}` },
      payload: {
        device_token: device.deviceToken,
        email: 'user@example.com',
        email_hash: 'email-hash',
        reason: 'biometric_failed',
      },
    })

    expect(res.statusCode).toBe(403)
    expect((res.json() as any).error.code).toBe('session_not_owned')
    expect((await prisma.verification.findUniqueOrThrow({ where: { id: session.id } })).state).toBe('INITIATED')
  })

  it('sign with App B\'s key against App A\'s device → 403 device_not_owned', async () => {
    const { device, sandboxWriteKeyB } = await setup()
    const res = await app.inject({
      method: 'POST', url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKeyB}` },
      payload: { device_token: device.deviceToken, context: 'transfer', canonicalized_payload: '{}' },
    })
    expect(res.statusCode).toBe(403)
    expect((res.json() as any).error.code).toBe('device_not_owned')
  })

  it('GET reputation with App B\'s read key against App A\'s device → 404 device_not_found', async () => {
    const { device, sandboxReadKeyB } = await setup()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/device/${device.deviceToken}/reputation`,
      headers: { authorization: `Bearer ${sandboxReadKeyB}` },
    })
    // 404 (not 403) so a sibling app can't probe for device existence via
    // differential error codes.
    expect(res.statusCode).toBe(404)
    expect((res.json() as any).error.code).toBe('device_not_found')
  })

  it('archived app rejects all SDK traffic with 401 app_archived', async () => {
    const { customer, appA, sandboxWriteKeyA } = await setup()
    await prisma.app.update({ where: { id: appA.id }, data: { archivedAt: new Date() } })

    // The auth plugin should refuse keys for an archived app, even before
    // we get to any handler. Use the verify route as a representative check.
    const res = await app.inject({
      method: 'POST', url: '/v1/verify',
      headers: { authorization: `Bearer ${sandboxWriteKeyA}` },
      payload: { device_token: 'anything', context: 'login' },
    })
    expect(res.statusCode).toBe(401)
    expect((res.json() as any).error.code).toBe('app_archived')
  })
})
