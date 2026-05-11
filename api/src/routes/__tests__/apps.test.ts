// /v1/customers/:id/apps/* — CRUD + archive lifecycle.
// Sister files cover attestation/Web SDK/confidence (apps.attestation.test.ts)
// and live keys (apps.live-keys.test.ts).

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import customerRoute from '../customers.js'
import appsRoute from '../apps.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip
const ADMIN_KEY = 'a'.repeat(64)

d('apps — CRUD + archive', () => {
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

  // ── POST /v1/customers/:id/apps ────────────────────────────────────────

  it('auto-generates slug from name', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Acme iOS' },
    })
    expect(res.statusCode).toBe(201)
    const body = res.json() as any
    expect(body.app.slug).toBe('acme-ios')
    expect(body.app.name).toBe('Acme iOS')
    expect(body.sandboxWriteKey).toMatch(/^vsk_sandbox_[0-9a-f]{40}$/)
    expect(body.sandboxReadKey).toMatch(/^vsk_sandbox_read_[0-9a-f]{40}$/)
  })

  it('accepts an explicit slug', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Production', slug: 'prod-1' },
    })
    expect(res.statusCode).toBe(201)
    expect((res.json() as any).app.slug).toBe('prod-1')
  })

  it('409 when explicit slug collides', async () => {
    const { customer } = await createSandboxCustomer()
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'A', slug: 'taken' },
    })
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'B', slug: 'taken' },
    })
    expect(res.statusCode).toBe(409)
    expect((res.json() as any).error.code).toBe('slug_conflict')
  })

  it('auto-suffixes slug to avoid collision when slug omitted', async () => {
    const { customer } = await createSandboxCustomer()
    // The customer fixture already has slug 'default'.
    const res1 = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Default' },
    })
    expect(res1.statusCode).toBe(201)
    expect((res1.json() as any).app.slug).toBe('default-2')
  })

  it('400 for reserved slug "new"', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'X', slug: 'new' },
    })
    expect(res.statusCode).toBe(400)
    expect((res.json() as any).error.code).toBe('invalid_field')
  })

  it('400 for reserved slug "archived"', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'X', slug: 'archived' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('400 for malformed slug (uppercase)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'X', slug: 'BadSlug' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('400 if name missing', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(400)
  })

  it('404 when customer missing', async () => {
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/cust_nonexistent/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Foo' },
    })
    expect(res.statusCode).toBe(404)
  })

  it('401 without admin key', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      payload: { name: 'X' },
    })
    expect(res.statusCode).toBe(401)
  })

  // ── GET /v1/customers/:id/apps ─────────────────────────────────────────

  it('list excludes archived by default', async () => {
    const { customer } = await createSandboxCustomer()
    // Default app already exists. Add a second, then archive one.
    const r2 = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Second' },
    })
    const secondId = (r2.json() as any).app.id
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${secondId}/archive`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const res = await app.inject({
      method: 'GET', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const apps = (res.json() as any).apps
    expect(apps).toHaveLength(1)
    expect(apps[0].slug).toBe('default')
  })

  it('list includes archived with includeArchived=true', async () => {
    const { customer } = await createSandboxCustomer()
    const r2 = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Second' },
    })
    const secondId = (r2.json() as any).app.id
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${secondId}/archive`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const res = await app.inject({
      method: 'GET', url: `/v1/customers/${customer.id}/apps?includeArchived=true`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect((res.json() as any).apps).toHaveLength(2)
  })

  // ── GET /v1/customers/:id/apps/:appId ──────────────────────────────────

  it('detail returns sandbox key prefixes only (no raw)', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET', url: `/v1/customers/${customer.id}/apps/${defaultApp.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.sandboxWriteKey).toBeUndefined()
    expect(body.sandboxReadKey).toBeUndefined()
    expect(body.sandboxWriteKeyPrefix).toMatch(/^vsk_sandbox_….*|^vsk_sandbox_/)
    expect(body.sandboxReadKeyPrefix).toMatch(/^vsk_sandbox_read_/)
  })

  it('404 for unknown app id', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'GET', url: `/v1/customers/${customer.id}/apps/app_does_not_exist`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(404)
  })

  // ── PATCH /v1/customers/:id/apps/:appId ────────────────────────────────

  it('PATCH updates name and slug', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH', url: `/v1/customers/${customer.id}/apps/${defaultApp.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Renamed', slug: 'renamed' },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.name).toBe('Renamed')
    expect(body.slug).toBe('renamed')
  })

  it('PATCH 409 when changing slug to a colliding one', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Other', slug: 'other' },
    })
    const res = await app.inject({
      method: 'PATCH', url: `/v1/customers/${customer.id}/apps/${defaultApp.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { slug: 'other' },
    })
    expect(res.statusCode).toBe(409)
  })

  it('PATCH 400 when changing slug to reserved word', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH', url: `/v1/customers/${customer.id}/apps/${defaultApp.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { slug: 'new' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('PATCH allows setting same slug as current (no-op)', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH', url: `/v1/customers/${customer.id}/apps/${defaultApp.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { slug: defaultApp.slug, description: 'desc' },
    })
    expect(res.statusCode).toBe(200)
  })

  it('PATCH 400 when no fields provided', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'PATCH', url: `/v1/customers/${customer.id}/apps/${defaultApp.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(400)
    expect((res.json() as any).error.code).toBe('no_fields')
  })

  // ── archive / unarchive ────────────────────────────────────────────────

  it('archive sets archivedAt', async () => {
    const { customer } = await createSandboxCustomer()
    // Create a second app so we can archive the first.
    const r2 = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Second' },
    })
    const secondId = (r2.json() as any).app.id
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${secondId}/archive`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    expect((res.json() as any).archivedAt).toBeTruthy()
  })

  it('archive 409 last_app on the only non-archived app', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${defaultApp.id}/archive`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(409)
    expect((res.json() as any).error.code).toBe('last_app')
  })

  it('unarchive clears archivedAt', async () => {
    const { customer } = await createSandboxCustomer()
    const r2 = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Second' },
    })
    const secondId = (r2.json() as any).app.id
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${secondId}/archive`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${secondId}/unarchive`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const detail = await app.inject({
      method: 'GET', url: `/v1/customers/${customer.id}/apps/${secondId}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect((detail.json() as any).archivedAt).toBeNull()
  })

  it('all endpoints reject without admin key', async () => {
    const { customer, app: defaultApp } = await createSandboxCustomer()
    const calls = [
      { method: 'GET',    url: `/v1/customers/${customer.id}/apps` },
      { method: 'GET',    url: `/v1/customers/${customer.id}/apps/${defaultApp.id}` },
      { method: 'PATCH',  url: `/v1/customers/${customer.id}/apps/${defaultApp.id}`, payload: { name: 'x' } },
      { method: 'POST',   url: `/v1/customers/${customer.id}/apps/${defaultApp.id}/archive` },
      { method: 'POST',   url: `/v1/customers/${customer.id}/apps/${defaultApp.id}/unarchive` },
    ] as const
    for (const c of calls) {
      const res = await app.inject(c as any)
      expect(res.statusCode).toBe(401)
    }
  })
})
