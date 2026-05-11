// /v1/sign respects App-level confidence policy. The SDK's
// `minimum_confidence` request param is still honoured — App policy raises
// the floor; it never lowers it.

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

d('POST /v1/sign — App confidence policy', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(signRoute, { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  async function deviceWithCeiling(ceiling: 'low' | 'medium' | 'high') {
    const { customer, app: a, sandboxWriteKey } = await createSandboxCustomer()
    const device = await prisma.device.create({
      data: {
        customerId: customer.id,
        appId: a.id,
        deviceToken: `dvt_${crypto.randomBytes(8).toString('hex')}`,
        publicKey: crypto.randomBytes(64).toString('base64'),
        keyFingerprint: crypto.randomBytes(32).toString('hex'),
        platform: 'web',
        confidenceCeiling: ceiling,
        attestationFormat: 'none',
        credentialId: 'cred_' + crypto.randomBytes(8).toString('hex'),
        status: 'active',
        enrolledAt: new Date(),
        isSandbox: true,
      },
    })
    return { customer, appRow: a, device, sandboxWriteKey }
  }

  it('App.signPayloadMinConfidence=high blocks medium device even if SDK omitted minimum_confidence', async () => {
    const { device, sandboxWriteKey } = await deviceWithCeiling('medium')
    // signPayloadMinConfidence defaults to 'high' on createSandboxCustomer
    const res = await app.inject({
      method: 'POST', url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: device.deviceToken, context: 'transfer', canonicalized_payload: '{}' },
    })
    expect(res.statusCode).toBe(422)
    expect((res.json() as any).error.code).toBe('verification_impossible')
  })

  it('App.signPayloadMinConfidence=low allows medium device when SDK omits minimum_confidence', async () => {
    const { device, appRow, sandboxWriteKey } = await deviceWithCeiling('medium')
    await prisma.app.update({ where: { id: appRow.id }, data: { signPayloadMinConfidence: 'low' } })
    const res = await app.inject({
      method: 'POST', url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: device.deviceToken, context: 'transfer', canonicalized_payload: '{}' },
    })
    expect(res.statusCode).toBe(200)
  })

  it('App context override raises floor for that context only', async () => {
    const { device, appRow, sandboxWriteKey } = await deviceWithCeiling('medium')
    await prisma.app.update({
      where: { id: appRow.id },
      data: {
        signPayloadMinConfidence: 'low',
        contextConfidenceOverrides: { transfer: 'high' },
      },
    })
    // 'login' uses the low default → succeeds.
    const r1 = await app.inject({
      method: 'POST', url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: device.deviceToken, context: 'login', canonicalized_payload: '{}' },
    })
    expect(r1.statusCode).toBe(200)
    // 'transfer' uses the high override → blocked.
    const r2 = await app.inject({
      method: 'POST', url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { device_token: device.deviceToken, context: 'transfer', canonicalized_payload: '{}' },
    })
    expect(r2.statusCode).toBe(422)
  })

  it('SDK request floor still wins when higher than App policy', async () => {
    const { device, appRow, sandboxWriteKey } = await deviceWithCeiling('medium')
    await prisma.app.update({ where: { id: appRow.id }, data: { signPayloadMinConfidence: 'low' } })
    const res = await app.inject({
      method: 'POST', url: '/v1/sign',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {
        device_token: device.deviceToken,
        context: 'login',
        canonicalized_payload: '{}',
        minimum_confidence: 'high',  // SDK demands high
      },
    })
    expect(res.statusCode).toBe(422)
  })
})
