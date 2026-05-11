// PATCH /v1/customers/:id covers customer-level fields only after the apps
// refactor. Attestation, Web SDK, and confidence policy fields moved to App
// and are tested in apps.attestation.test.ts.

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import customerRoute from '../customers.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip
const ADMIN_KEY = 'a'.repeat(64)

d('PATCH /v1/customers/:id — customer-level fields', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    process.env.ADMIN_KEY = ADMIN_KEY
    app = await buildTestApp(async (fastify) => {
      await fastify.register(customerRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('updates orgName and billingEmail', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { orgName: 'Acme Inc', billingEmail: 'billing@acme.com' },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as Record<string, unknown>
    expect(body.orgName).toBe('Acme Inc')
    expect(body.billingEmail).toBe('billing@acme.com')
  })

  it('updates minimumConfidence', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { minimumConfidence: 'high' },
    })
    expect(res.statusCode).toBe(200)
    expect((res.json() as any).minimumConfidence).toBe('high')
  })

  it('updates networkOptIn', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { networkOptIn: false },
    })
    expect(res.statusCode).toBe(200)
    expect((res.json() as any).networkOptIn).toBe(false)
  })

  it('400 when no fields are provided', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(400)
    expect((res.json() as any).error.code).toBe('no_fields')
  })

  it('rejects requests without the admin key', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      payload: { orgName: 'Hax' },
    })
    expect(res.statusCode).toBe(401)
  })

  it('rejects requests with the wrong admin key', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH',
      url: `/v1/customers/${customer.id}`,
      headers: { authorization: 'Bearer wrong' },
      payload: { orgName: 'Hax' },
    })
    expect(res.statusCode).toBe(401)
  })
})
