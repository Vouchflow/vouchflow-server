// GET /v1/device/:device_token/reputation — last_verification must resolve
// a completed email-OTP fallback (state FALLBACK_COMPLETE), not just a
// biometric/signed-challenge completion (state COMPLETED). Regression for
// the two lookups (here and verify.ts's /verify/:session_id) drifting on
// what counts as "verified".

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import deviceRoute from '../device.js'
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
