// GET /v1/customers/:id/overview — customer-wide aggregation across all
// non-archived apps. Admin-keyed.

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import crypto from 'node:crypto'
import customerRoute from '../customers.js'
import appsRoute from '../apps.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
  createDevice,
  createVerification,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip
const ADMIN_KEY = 'a'.repeat(64)

d('GET /v1/customers/:id/overview', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    process.env.ADMIN_KEY = ADMIN_KEY
    app = await buildTestApp(async (fastify) => {
      await fastify.register(customerRoute, { prefix: '/v1' })
      await fastify.register(appsRoute,     { prefix: '/v1' })
    })
  })
  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('returns zeros for a customer with no apps', async () => {
    const customer = await prisma.customer.create({ data: { email: 'noapp@test.local' } })
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/overview?range=7d&env=sandbox`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.appCount).toBe(0)
    expect(body.verificationCount).toBe(0)
    expect(body.deviceCount).toBe(0)
    expect(body.perApp).toEqual([])
  })

  it('aggregates verifications and devices across two apps', async () => {
    const { customer, app: appA } = await createSandboxCustomer()
    // Add a second app via direct Prisma (cheaper than going through POST).
    const appB = await prisma.app.create({
      data: {
        customerId: customer.id,
        name: 'B', slug: 'b',
        sandboxWriteKey: `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`,
        sandboxReadKey:  `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`,
      },
    })

    // App A: 2 devices, 2 successful verifications.
    const dA1 = await createDevice(customer.id, { appId: appA.id })
    const dA2 = await createDevice(customer.id, { appId: appA.id })
    await createVerification(customer.id, dA1.id, { appId: appA.id, state: 'COMPLETED', confidence: 'high' })
    await createVerification(customer.id, dA2.id, { appId: appA.id, state: 'COMPLETED', confidence: 'high' })

    // App B: 1 device, 1 successful + 1 failed.
    const dB1 = await createDevice(customer.id, { appId: appB.id })
    await createVerification(customer.id, dB1.id, { appId: appB.id, state: 'COMPLETED', confidence: 'medium' })
    await createVerification(customer.id, dB1.id, { appId: appB.id, state: 'FAILED', confidence: null })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/overview?range=7d&env=sandbox`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.appCount).toBe(2)
    expect(body.verificationCount).toBe(3)  // successes only
    expect(body.deviceCount).toBe(3)
    // Success: 3, failure: 1 → 75%
    expect(body.successRatePct).toBeCloseTo(75, 1)
    // High-confidence: 2 of 3 with confidence set → ~66.7%
    expect(body.highConfidencePct).toBeCloseTo(66.67, 1)
    // perApp groups by appId
    expect(body.perApp).toHaveLength(2)
    const counts = Object.fromEntries(body.perApp.map((r: any) => [r.appId, r.verificationCount]))
    expect(counts[appA.id]).toBe(2)
    expect(counts[appB.id]).toBe(1)
  })

  it('excludes archived apps', async () => {
    const { customer, app: appA } = await createSandboxCustomer()
    const appB = await prisma.app.create({
      data: {
        customerId: customer.id,
        name: 'B', slug: 'b',
        sandboxWriteKey: `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`,
        sandboxReadKey:  `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`,
        archivedAt: new Date(),
      },
    })
    const dB = await createDevice(customer.id, { appId: appB.id })
    await createVerification(customer.id, dB.id, { appId: appB.id, state: 'COMPLETED', confidence: 'high' })
    // App A has no data.

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/overview?range=7d`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const body = res.json() as any
    expect(body.appCount).toBe(1) // only appA
    expect(body.verificationCount).toBe(0) // archived appB's data excluded
  })

  it('rejects invalid range', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/overview?range=4w`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(400)
  })

  it('401 without admin key', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/overview`,
    })
    expect(res.statusCode).toBe(401)
  })
})
