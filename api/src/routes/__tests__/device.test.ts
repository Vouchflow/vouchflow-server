// GET /v1/device/:device_token/reputation — last_verification must resolve
// a completed email-OTP fallback (state FALLBACK_COMPLETE), not just a
// biometric/signed-challenge completion (state COMPLETED). Regression for
// the two lookups (here and verify.ts's /verify/:session_id) drifting on
// what counts as "verified".

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import deviceRoute from '../device.js'
import verifyRoute from '../verify.js'
import { prisma } from '../../lib/prisma.js'
import { hashOtp } from '../../services/otp.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
  createDevice,
  createVerification,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

d('GET /v1/device/:device_token/reputation — last_verification', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(deviceRoute, { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('finds a fallback-completed verification (state FALLBACK_COMPLETE)', async () => {
    const { customer, sandboxReadKey } = await createSandboxCustomer()
    const device = await createDevice(customer.id)
    await createVerification(customer.id, device.id, {
      state: 'FALLBACK_COMPLETE',
      confidence: 'low',
      biometricUsed: false,
      fallbackUsed: true,
    })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/device/${device.deviceToken}/reputation`,
      headers: { authorization: `Bearer ${sandboxReadKey}` },
    })

    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.last_verification).not.toBeNull()
    expect(body.last_verification.fallback_used).toBe(true)
    expect(body.last_verification.confidence).toBe('low')
  })

  it('still finds a normal completed verification (state COMPLETED, no regression)', async () => {
    const { customer, sandboxReadKey } = await createSandboxCustomer()
    const device = await createDevice(customer.id)
    await createVerification(customer.id, device.id, {
      state: 'COMPLETED',
      confidence: 'high',
      biometricUsed: true,
      fallbackUsed: false,
    })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/device/${device.deviceToken}/reputation`,
      headers: { authorization: `Bearer ${sandboxReadKey}` },
    })

    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.last_verification).not.toBeNull()
    expect(body.last_verification.fallback_used).toBe(false)
    expect(body.last_verification.confidence).toBe('high')
  })
})

// POST /v1/verify/:session_id/complete (fallback OTP path) must refresh
// device.lastSeen on success, same as the primary biometric completion path —
// the fallback branch previously skipped this update entirely.
d('POST /v1/verify/:session_id/complete — fallback completion refreshes device.lastSeen', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(verifyRoute, { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('updates device.lastSeen after a successful OTP completion', async () => {
    const { customer, app: sandboxApp, sandboxWriteKey } = await createSandboxCustomer()
    const device = await createDevice(customer.id, { appId: sandboxApp.id })
    expect(device.lastSeen).toBeNull()

    const session = await createVerification(customer.id, device.id, {
      appId: sandboxApp.id,
      state: 'FALLBACK',
      completedAt: null,
    })
    await prisma.verification.update({
      where: { id: session.id },
      data: {
        otpHash: hashOtp('123456'),
        otpExpiresAt: new Date(Date.now() + 60_000),
        otpAttempts: 0,
      },
    })

    const beforeComplete = new Date()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/verify/${session.sessionId}/complete`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: device.deviceToken, otp: '123456' },
    })

    expect(res.statusCode).toBe(200)
    expect((res.json() as any).session_state).toBe('FALLBACK_COMPLETE')

    const updatedDevice = await prisma.device.findUniqueOrThrow({ where: { id: device.id } })
    expect(updatedDevice.lastSeen).not.toBeNull()
    expect(updatedDevice.lastSeen!.getTime()).toBeGreaterThanOrEqual(beforeComplete.getTime())
  })
})
