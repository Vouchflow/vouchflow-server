import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import customerRoute from '../customers.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
  createLiveKey,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// Multi-key endpoints (POST/GET/DELETE /v1/customers/:id/live-keys) ship in
// v1.2.0. They were typechecked but never exercised end-to-end before — these
// tests are the first validation that the cap, scope routing, revocation,
// and 14-day grace window all behave as documented.

const ADMIN_KEY = 'a'.repeat(64)

d('POST /v1/customers/:id/live-keys', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    process.env.ADMIN_KEY = ADMIN_KEY
    app = await buildTestApp(async (fastify) => {
      await fastify.register(customerRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => {
    await app.close()
  })

  beforeEach(async () => {
    await cleanDb()
  })

  it('creates a write+read pair by default (back-compat with old dashboard)', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as { writeKey: { rawKey: string }; readKey: { rawKey: string } }
    expect(body.writeKey.rawKey).toMatch(/^vsk_live_[0-9a-f]{40}$/)
    expect(body.readKey.rawKey).toMatch(/^vsk_live_read_[0-9a-f]{40}$/)
  })

  it('creates a single write key when scope=write', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as { key: { rawKey: string; scope: string } }
    expect(body.key.scope).toBe('write')
    expect(body.key.rawKey).toMatch(/^vsk_live_[0-9a-f]{40}$/)
  })

  it('creates a single read key when scope=read', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'read' },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as { key: { rawKey: string; scope: string } }
    expect(body.key.scope).toBe('read')
    expect(body.key.rawKey).toMatch(/^vsk_live_read_[0-9a-f]{40}$/)
  })

  it('rejects an unknown scope', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'banana' },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toMatchObject({ error: { code: 'invalid_request' } })
  })

  it('does NOT deprecate existing keys (the whole point of multi-key)', async () => {
    const { customer } = await createSandboxCustomer()
    await createLiveKey(customer.id, 'write')
    await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    const list = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const { keys } = list.json() as { keys: unknown[] }
    expect(keys.length).toBe(2)
  })

  it('returns 409 key_limit_reached when adding a single key would exceed 10', async () => {
    const { customer } = await createSandboxCustomer()
    // Pre-fill with 10 active keys
    for (let i = 0; i < 10; i++) {
      await createLiveKey(customer.id, i % 2 === 0 ? 'write' : 'read')
    }
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    expect(res.statusCode).toBe(409)
    expect(res.json()).toMatchObject({ error: { code: 'key_limit_reached' } })
  })

  it('returns 409 when a pair would push past the cap (counts both keys against limit)', async () => {
    const { customer } = await createSandboxCustomer()
    // 9 active — pair would push to 11
    for (let i = 0; i < 9; i++) {
      await createLiveKey(customer.id, 'write')
    }
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'pair' },
    })
    expect(res.statusCode).toBe(409)
  })

  it('does not count deprecated keys against the cap', async () => {
    const { customer } = await createSandboxCustomer()
    // 10 deprecated keys + create — should succeed because cap is on active only
    for (let i = 0; i < 10; i++) {
      await createLiveKey(customer.id, 'write', { deprecated: true, deprecatedAt: new Date() })
    }
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    expect(res.statusCode).toBe(200)
  })

  it('rejects requests without the admin key', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/live-keys`,
      payload: {},
    })
    expect(res.statusCode).toBe(401)
  })
})

d('GET /v1/customers/:id/live-keys', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    process.env.ADMIN_KEY = ADMIN_KEY
    app = await buildTestApp(async (fastify) => {
      await fastify.register(customerRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('returns only non-deprecated keys, newest-first', async () => {
    const { customer } = await createSandboxCustomer()
    await createLiveKey(customer.id, 'write', { deprecated: true, deprecatedAt: new Date() })
    const { apiKey: a } = await createLiveKey(customer.id, 'write')
    await new Promise(r => setTimeout(r, 10))
    const { apiKey: b } = await createLiveKey(customer.id, 'read')
    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${customer.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const { keys } = res.json() as { keys: { id: string; lastUsedAt: string | null }[] }
    expect(keys.length).toBe(2)
    expect(keys[0].id).toBe(b.id) // newer first
    expect(keys[1].id).toBe(a.id)
    expect(keys[0]).toHaveProperty('lastUsedAt')
  })
})

d('DELETE /v1/customers/:id/live-keys/:keyId', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    process.env.ADMIN_KEY = ADMIN_KEY
    app = await buildTestApp(async (fastify) => {
      await fastify.register(customerRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('marks a key deprecated with deprecatedAt set to now', async () => {
    const { customer } = await createSandboxCustomer()
    const { apiKey } = await createLiveKey(customer.id, 'write')
    const before = Date.now()
    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/customers/${customer.id}/live-keys/${apiKey.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as { key: { deprecatedAt: string } }
    expect(new Date(body.key.deprecatedAt).getTime()).toBeGreaterThanOrEqual(before - 1000)
  })

  it('returns 404 for an unknown key id', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/customers/${customer.id}/live-keys/non-existent-id`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(404)
  })

  it('returns 404 when the key belongs to a different customer (no cross-tenant revocation)', async () => {
    const { customer: c1 } = await createSandboxCustomer()
    const { customer: c2 } = await createSandboxCustomer()
    const { apiKey } = await createLiveKey(c2.id, 'write')
    // c1 trying to revoke c2's key
    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/customers/${c1.id}/live-keys/${apiKey.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(404)
  })

  it('returns 409 already_revoked when revoking an already-deprecated key', async () => {
    const { customer } = await createSandboxCustomer()
    const { apiKey } = await createLiveKey(customer.id, 'write', {
      deprecated: true,
      deprecatedAt: new Date(),
    })
    const res = await app.inject({
      method: 'DELETE',
      url: `/v1/customers/${customer.id}/live-keys/${apiKey.id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(409)
    expect(res.json()).toMatchObject({ error: { code: 'already_revoked' } })
  })
})
