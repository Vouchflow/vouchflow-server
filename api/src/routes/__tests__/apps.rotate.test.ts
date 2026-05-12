// Tests for the at-most-one-canonical-key rotation flow added in the
// live-keys refactor. Covers:
// - POST /apps creates 1 write + 1 read live key automatically.
// - POST /live-keys/rotate generates a new key + deprecates the old.
// - Pair keys are auto-split on first rotation of either scope.
// - POST /live-keys/generate is idempotent-blocked once any active key exists.
// - GET /live-keys returns all keys (active + deprecated-in-grace).

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import customerRoute from '../customers.js'
import appsRoute from '../apps.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip
const ADMIN_KEY = 'a'.repeat(64)

d('apps live-keys — rotate + auto-create + lazy-generate', () => {
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

  // Helper — creates a fresh customer + app + returns ids.
  async function freshApp() {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'My App' },
    })
    expect(res.statusCode).toBe(201)
    const body = res.json() as any
    return {
      customerId: customer.id,
      appId:      body.app.id,
      writeKey:   body.liveWriteKey as string,
      readKey:    body.liveReadKey  as string,
    }
  }

  // ── auto-create on POST /apps ────────────────────────────────────────

  it('POST /apps auto-generates one live write + one live read key', async () => {
    const { customer } = await createSandboxCustomer()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/apps`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { name: 'Acme' },
    })
    expect(res.statusCode).toBe(201)
    const body = res.json() as any
    expect(body.liveWriteKey).toMatch(/^vsk_live_[0-9a-f]{40}$/)
    expect(body.liveReadKey).toMatch(/^vsk_live_read_[0-9a-f]{40}$/)
    expect(body.sandboxWriteKey).toMatch(/^vsk_sandbox_[0-9a-f]{40}$/)
    expect(body.sandboxReadKey).toMatch(/^vsk_sandbox_read_[0-9a-f]{40}$/)
    // Persisted as ApiKey rows with correct scope.
    const keys = await prisma.apiKey.findMany({
      where: { appId: body.app.id },
      orderBy: { scope: 'asc' },
    })
    expect(keys).toHaveLength(2)
    expect(keys.map(k => k.scope).sort()).toEqual(['read', 'write'])
    expect(keys.every(k => !k.deprecated)).toBe(true)
  })

  // ── rotate ───────────────────────────────────────────────────────────

  it('POST /live-keys/rotate (write) creates a new key + deprecates the old', async () => {
    const f = await freshApp()
    const before = await prisma.apiKey.findMany({ where: { appId: f.appId, scope: 'write' } })
    expect(before).toHaveLength(1)
    const oldId = before[0]!.id

    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${f.customerId}/apps/${f.appId}/live-keys/rotate`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    expect(body.key.rawKey).toMatch(/^vsk_live_[0-9a-f]{40}$/)
    expect(body.key.scope).toBe('write')
    expect(body.deprecated.id).toBe(oldId)
    expect(body.deprecated.deprecatedAt).toBeTruthy()

    // DB state: 1 active + 1 deprecated, both scope=write.
    const all = await prisma.apiKey.findMany({ where: { appId: f.appId, scope: 'write' } })
    expect(all).toHaveLength(2)
    const active = all.filter(k => !k.deprecated)
    expect(active).toHaveLength(1)
    expect(active[0]!.id).not.toBe(oldId)
  })

  it('rotate read scope independently of write', async () => {
    const f = await freshApp()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${f.customerId}/apps/${f.appId}/live-keys/rotate`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'read' },
    })
    expect(res.statusCode).toBe(200)
    expect((res.json() as any).key.rawKey).toMatch(/^vsk_live_read_[0-9a-f]{40}$/)

    // Write key untouched.
    const writes = await prisma.apiKey.findMany({ where: { appId: f.appId, scope: 'write' } })
    expect(writes).toHaveLength(1)
    expect(writes[0]!.deprecated).toBe(false)
  })

  it('rejects unknown scope', async () => {
    const f = await freshApp()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${f.customerId}/apps/${f.appId}/live-keys/rotate`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'pair' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('rotation works on app with no keys yet (creates the first one)', async () => {
    // Manually create an app without live keys (simulates a backfilled app
    // whose canonical keys were never auto-created).
    const { customer } = await createSandboxCustomer()
    const created = await prisma.app.create({
      data: {
        customerId: customer.id, name: 'Bare', slug: 'bare',
        sandboxWriteKey: 'vsk_sandbox_x'.padEnd(52, '0'),
        sandboxReadKey:  'vsk_sandbox_read_x'.padEnd(57, '0'),
        signPayloadMinConfidence: 'high',
      },
    })
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/apps/${created.id}/live-keys/rotate`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    expect(res.statusCode).toBe(200)
    expect((res.json() as any).deprecated).toBeNull()
  })

  // ── pair-key auto-split on first rotation ────────────────────────────

  it('rotating either scope auto-splits an existing pair key', async () => {
    const { customer } = await createSandboxCustomer()
    const created = await prisma.app.create({
      data: {
        customerId: customer.id, name: 'Pair', slug: 'pair',
        sandboxWriteKey: 'vsk_sandbox_p'.padEnd(52, '0'),
        sandboxReadKey:  'vsk_sandbox_read_p'.padEnd(57, '0'),
        signPayloadMinConfidence: 'high',
        apiKeys: { create: [{ customerId: customer.id, keyHash: 'pair_hash', scope: 'pair' }] },
      },
    })

    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/apps/${created.id}/live-keys/rotate`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as any
    // Returns the new write key + a *companion* read key (the auto-split).
    expect(body.key.scope).toBe('write')
    expect(body.companion?.scope).toBe('read')
    expect(body.deprecated.scope).toBe('pair')

    const all = await prisma.apiKey.findMany({ where: { appId: created.id } })
    expect(all).toHaveLength(3) // pair (deprecated) + new write + new read
    const active = all.filter(k => !k.deprecated)
    expect(active.map(k => k.scope).sort()).toEqual(['read', 'write'])
  })

  // ── generate (lazy initial creation) ─────────────────────────────────

  it('POST /live-keys/generate fails if active keys already exist', async () => {
    const f = await freshApp()
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${f.customerId}/apps/${f.appId}/live-keys/generate`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(409)
    expect((res.json() as any).error.code).toBe('keys_already_exist')
  })

  it('POST /live-keys/generate creates a write+read pair on a bare app', async () => {
    const { customer } = await createSandboxCustomer()
    const created = await prisma.app.create({
      data: {
        customerId: customer.id, name: 'Bare2', slug: 'bare2',
        sandboxWriteKey: 'vsk_sandbox_y'.padEnd(52, '0'),
        sandboxReadKey:  'vsk_sandbox_read_y'.padEnd(57, '0'),
        signPayloadMinConfidence: 'high',
      },
    })
    const res = await app.inject({
      method: 'POST',
      url: `/v1/customers/${customer.id}/apps/${created.id}/live-keys/generate`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(201)
    const body = res.json() as any
    expect(body.liveWriteKey).toMatch(/^vsk_live_[0-9a-f]{40}$/)
    expect(body.liveReadKey).toMatch(/^vsk_live_read_[0-9a-f]{40}$/)
    const keys = await prisma.apiKey.findMany({ where: { appId: created.id } })
    expect(keys).toHaveLength(2)
  })

  // ── GET /live-keys returns all (incl. deprecated) ───────────────────

  it('GET /live-keys returns active and deprecated keys with deprecation metadata', async () => {
    const f = await freshApp()
    // Rotate write so we have one deprecated.
    await app.inject({
      method: 'POST',
      url: `/v1/customers/${f.customerId}/apps/${f.appId}/live-keys/rotate`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { scope: 'write' },
    })

    const res = await app.inject({
      method: 'GET',
      url: `/v1/customers/${f.customerId}/apps/${f.appId}/live-keys`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const { keys } = res.json() as any
    expect(keys).toHaveLength(3) // 1 active write + 1 active read + 1 deprecated write

    const deprecatedKeys = keys.filter((k: any) => k.deprecated)
    expect(deprecatedKeys).toHaveLength(1)
    expect(deprecatedKeys[0].scope).toBe('write')
    expect(deprecatedKeys[0].deprecatedAt).toBeTruthy()

    const activeKeys = keys.filter((k: any) => !k.deprecated)
    expect(activeKeys).toHaveLength(2)
    expect(activeKeys.map((k: any) => k.scope).sort()).toEqual(['read', 'write'])
  })
})
