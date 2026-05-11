// Customer-scoped live-key endpoints became a deprecation shim in the apps
// refactor. Live keys belong to an App; the shim either redirects (308) to
// the app-scoped endpoint when the customer has exactly one non-archived
// app, or returns 409 ambiguous_app when the caller must pick.
//
// These tests pin the shim behaviour. Fastify's inject does not follow
// redirects by default — statusCode 308 is the expected outcome.

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import customerRoute from '../customers.js'
import appsRoute from '../apps.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
  createLiveKey,
} from '../../__tests__/helpers/testApp.js'
import { prisma } from '../../lib/prisma.js'

const d = HAS_DB ? describe : describe.skip
const ADMIN_KEY = 'a'.repeat(64)

d('customer-scoped live-keys (deprecation shim)', () => {
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

  // ── single-app: 308 redirect ──────────────────────────────────────────

  it('POST 308 → app-scoped endpoint when customer has exactly one app', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(308)
    expect(res.headers.location).toBe(`/v1/customers/${customer.id}/apps/${defaultApp.id}/live-keys`)
    expect(res.headers['vouchflow-deprecation']).toBe('customer-scoped-live-keys')
  })

  it('GET 308 → app-scoped endpoint when customer has exactly one app', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(308)
    expect(res.headers.location).toBe(`/v1/customers/${customer.id}/apps/${defaultApp.id}/live-keys`)
  })

  // ── multi-app: 409 ambiguous_app ──────────────────────────────────────

  it('POST 409 ambiguous_app when customer has 2+ non-archived apps', async () => {
    const { customer } = await createSandboxCustomer()
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Second' },
    })
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(409)
    const body = res.json() as any
    expect(body.error.code).toBe('ambiguous_app')
    expect(body.apps).toHaveLength(2)
    expect(body.apps[0]).toMatchObject({ id: expect.any(String), name: expect.any(String) })
  })

  it('GET 409 ambiguous_app when customer has 2+ non-archived apps', async () => {
    const { customer } = await createSandboxCustomer()
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Second' },
    })
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(409)
  })

  // ── no-apps edge case ─────────────────────────────────────────────────

  it('POST 409 no_app when customer has zero non-archived apps', async () => {
    const customer = await prisma.customer.create({
      data: { email: 'noapp@test.local' },
    })
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(409)
    expect((res.json() as any).error.code).toBe('no_app')
  })

  // ── DELETE shim: redirects unambiguously regardless of app count ──────

  it('DELETE 308 → app-scoped endpoint, using the key\'s app', async () => {
    const { customer } = await createSandboxCustomer()
    const { apiKey } = await createLiveKey(customer.id, 'write')
    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/customers/${customer.id}/live-keys/${apiKey.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(308)
    expect(res.headers.location).toBe(`/v1/customers/${customer.id}/apps/${apiKey.appId}/live-keys/${apiKey.id}`)
    expect(res.headers['vouchflow-deprecation']).toBe('customer-scoped-live-keys')
  })

  it('DELETE 308 even when the customer has multiple apps (key\'s app is unambiguous)', async () => {
    const { customer } = await createSandboxCustomer()
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'B' },
    })
    const { apiKey } = await createLiveKey(customer.id, 'write')
    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/customers/${customer.id}/live-keys/${apiKey.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(308)
  })

  it('DELETE 404 for unknown key id', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/customers/${customer.id}/live-keys/cm_nonexistent`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(404)
  })

  it('DELETE 404 when the key belongs to a different customer', async () => {
    const { customer: c1 } = await createSandboxCustomer()
    const { customer: c2 } = await createSandboxCustomer()
    const { apiKey } = await createLiveKey(c2.id, 'write')
    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/customers/${c1.id}/live-keys/${apiKey.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(404)
  })

  // ── auth ──────────────────────────────────────────────────────────────

  it('rejects requests without the admin key', async () => {
    const { customer } = await createSandboxCustomer()
    const r1 = await app.inject({ method: 'POST',   url: `/v1/customers/${customer.id}/live-keys`, payload: {} })
    const r2 = await app.inject({ method: 'GET',    url: `/v1/customers/${customer.id}/live-keys` })
    const r3 = await app.inject({ method: 'DELETE', url: `/v1/customers/${customer.id}/live-keys/anything` })
    expect(r1.statusCode).toBe(401)
    expect(r2.statusCode).toBe(401)
    expect(r3.statusCode).toBe(401)
  })
})
