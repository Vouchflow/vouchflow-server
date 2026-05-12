// /v1/customers/:id/apps/:appId/live-keys — per-app live key lifecycle.

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

d('apps live-keys', () => {
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

  it('POST default scope creates a write+read pair', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.writeKey.rawKey).toMatch(/^vsk_live_[0-9a-f]{40}$/)
    expect(body.readKey.rawKey).toMatch(/^vsk_live_read_[0-9a-f]{40}$/)
    expect(body.writeKey.scope).toBe('write')
    expect(body.readKey.scope).toBe('read')
  })

  it('POST { scope: "write" } creates a single write key', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.key.scope).toBe('write')
    expect(body.key.rawKey).toMatch(/^vsk_live_[0-9a-f]{40}$/)
    expect(body.writeKey).toBeUndefined()
  })

  it('POST { scope: "read" } creates a single read key', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'read' },
    })
    expect(res.statusCode).toBe(200)
    expect((res.json() as any).key.scope).toBe('read')
  })

  it('POST { scope: "invalid" } → 400', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'admin' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('21st key → 409 key_limit_reached (cap is 20)', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    // App auto-created with 2 keys (write + read). Create 9 more pairs = 18 more keys.
    // Total = 20 keys. Then try to add one more → should hit limit.
    for (let i = 0; i < 9; i++) {
      const r = await app.inject({
        method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
        headers: { authorization: `Bearer ${ADMIN_KEY}` },
        payload: {},
      })
      expect(r.statusCode).toBe(200)
    }
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    expect(res.statusCode).toBe(409)
    expect((res.json() as any).error.code).toBe('key_limit_reached')
  })

  it('POST against archived app → 409 app_archived', async () => {
    const { customer } = await createSandboxCustomer()
    // Create a second app, archive it.
    const r2 = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Old' },
    })
    const oldId = (r2.json() as any).app.id
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${oldId}/archive`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${oldId}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    expect(res.statusCode).toBe(409)
    expect((res.json() as any).error.code).toBe('app_archived')
  })

  it('GET includes deprecated keys (for 14-day grace display)', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const create = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    const writeKeyId = (create.json() as any).writeKey.id
    await app.inject({
      method: 'DELETE', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys/${writeKeyId}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const list = await app.inject({
      method: 'GET', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const keys = (list.json() as any).keys
    const deprecatedKey = keys.find((k: any) => k.id === writeKeyId)
    expect(deprecatedKey).toBeDefined()
    expect(deprecatedKey.deprecated).toBe(true)
    expect(deprecatedKey.deprecatedAt).toBeTruthy()
    expect(keys).toHaveLength(2) // 1 active readKey + 1 deprecated writeKey
  })

  it('DELETE marks deprecated and returns deprecatedAt; second DELETE → 409', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const create = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    const keyId = (create.json() as any).key.id
    const del1 = await app.inject({
      method: 'DELETE', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys/${keyId}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(del1.statusCode).toBe(200)
    expect((del1.json() as any).key.deprecatedAt).toBeTruthy()
    const del2 = await app.inject({
      method: 'DELETE', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys/${keyId}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(del2.statusCode).toBe(409)
    expect((del2.json() as any).error.code).toBe('already_revoked')
  })

  it('DELETE on key from a different app → 404', async () => {
    const { customer, app: appA } = await createSandboxCustomer()
    const r2 = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'B' },
    })
    const appBId = (r2.json() as any).app.id
    const create = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${appA.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    const keyId = (create.json() as any).key.id
    const res = await app.inject({
      method: 'DELETE', url: `/v1/customers/${customer.id}/apps/${appBId}/live-keys/${keyId}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(404)
  })

  it('cross-app isolation: GET on app B does not see app A\'s keys', async () => {
    const { customer, app: appA } = await createSandboxCustomer()
    const r2 = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'B' },
    })
    const appBId = (r2.json() as any).app.id
    await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${appA.id}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: {},
    })
    const list = await app.inject({
      method: 'GET', url: `/v1/customers/${customer.id}/apps/${appBId}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect((list.json() as any).keys).toHaveLength(0)
  })

  it('401 without admin key', async () => {
    const { customer, app: a } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST', url: `/v1/customers/${customer.id}/apps/${a.id}/live-keys`,
      payload: {},
    })
    expect(res.statusCode).toBe(401)
  })
})
