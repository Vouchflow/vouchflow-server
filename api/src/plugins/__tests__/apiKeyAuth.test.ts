import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import { makeApiKeyAuthPlugin } from '../apiKeyAuth.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
  createLiveKey,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// API key auth is the gate that maps an inbound API key to a customerId and
// scope. A bug here is total compromise — wrong customer charged, wrong
// data returned, write endpoints accepting read keys, etc. Cover every
// branch with a real Fastify request.

d('apiKeyAuth: write-scoped endpoint', () => {
  let writeApp: FastifyInstance
  let readApp: FastifyInstance

  beforeAll(async () => {
    // A tiny test plugin: applies the auth middleware, then echoes whatever
    // it stamped on the request. That way each test asserts on the same
    // shape (or the auth-fail status code).
    writeApp = await buildTestApp(async (fastify) => {
      await fastify.register(makeApiKeyAuthPlugin('write'))
      fastify.post('/test', async (req) => ({
        customerId: req.customerId,
        apiKeyId: req.apiKeyId,
        isSandbox: req.isSandbox,
        deprecated: req.apiKeyDeprecated,
      }))
    })
    readApp = await buildTestApp(async (fastify) => {
      await fastify.register(makeApiKeyAuthPlugin('read'))
      fastify.get('/test', async (req) => ({
        customerId: req.customerId,
        apiKeyId: req.apiKeyId,
        isSandbox: req.isSandbox,
        deprecated: req.apiKeyDeprecated,
      }))
    })
  })

  afterAll(async () => {
    await writeApp.close()
    await readApp.close()
  })

  beforeEach(async () => {
    await cleanDb()
  })

  // ── Sandbox keys ────────────────────────────────────────────────────────

  it('accepts a sandbox write key on a write endpoint', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as { customerId: string; isSandbox: boolean; apiKeyId: string }
    expect(body.customerId).toBe(customer.id)
    expect(body.isSandbox).toBe(true)
    expect(body.apiKeyId).toBe(`sandbox:${customer.id}`)
  })

  it('rejects a sandbox READ key on a write endpoint with insufficient_scope', async () => {
    const { sandboxReadKey } = await createSandboxCustomer()
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: `Bearer ${sandboxReadKey}` },
    })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ error: { code: 'insufficient_scope' } })
  })

  // ── Scope hierarchy: write satisfies read ──────────────────────────────

  it('accepts a sandbox WRITE key on a read endpoint (write is privileged)', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const res = await readApp.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ customerId: customer.id })
  })

  it('accepts a live WRITE key on a read endpoint', async () => {
    const { customer } = await createSandboxCustomer()
    const { rawKey } = await createLiveKey(customer.id, 'write')
    const res = await readApp.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `Bearer ${rawKey}` },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ customerId: customer.id })
  })

  it('accepts a sandbox read key on a read endpoint', async () => {
    const { customer, sandboxReadKey } = await createSandboxCustomer()
    const res = await readApp.inject({
      method: 'GET',
      url: '/test',
      headers: { authorization: `Bearer ${sandboxReadKey}` },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ customerId: customer.id, isSandbox: true })
  })

  it('rejects an unknown sandbox-prefixed key with invalid_api_key', async () => {
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: 'Bearer vsk_sandbox_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' },
    })
    expect(res.statusCode).toBe(401)
    expect(res.json()).toMatchObject({ error: { code: 'invalid_api_key' } })
  })

  // ── Live keys ──────────────────────────────────────────────────────────

  it('accepts a live write key on a write endpoint', async () => {
    const { customer } = await createSandboxCustomer()
    const { rawKey, apiKey } = await createLiveKey(customer.id, 'write')
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: `Bearer ${rawKey}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as { customerId: string; apiKeyId: string; isSandbox: boolean }
    expect(body.customerId).toBe(customer.id)
    expect(body.apiKeyId).toBe(apiKey.id)
    expect(body.isSandbox).toBe(false)
  })

  it('rejects a live READ key on a write endpoint', async () => {
    const { customer } = await createSandboxCustomer()
    const { rawKey } = await createLiveKey(customer.id, 'read')
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: `Bearer ${rawKey}` },
    })
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ error: { code: 'insufficient_scope' } })
  })

  it('rejects an unknown live key with invalid_api_key', async () => {
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: 'Bearer vsk_live_unknown_unknown_unknown_unknown_unknown' },
    })
    expect(res.statusCode).toBe(401)
    expect(res.json()).toMatchObject({ error: { code: 'invalid_api_key' } })
  })

  // ── Deprecated key grace window (§13: 14 days) ─────────────────────────

  it('accepts a deprecated key WITHIN the 14-day grace window', async () => {
    const { customer } = await createSandboxCustomer()
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000)
    const { rawKey } = await createLiveKey(customer.id, 'write', {
      deprecated: true,
      deprecatedAt: yesterday,
    })
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: `Bearer ${rawKey}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json() as { deprecated: boolean }
    expect(body.deprecated).toBe(true)
    // §13: SDK detects rotation via this header
    expect(res.headers['vouchflow-key-deprecated']).toBe('true')
  })

  it('rejects a deprecated key BEYOND the 14-day grace window', async () => {
    const { customer } = await createSandboxCustomer()
    const longAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    const { rawKey } = await createLiveKey(customer.id, 'write', {
      deprecated: true,
      deprecatedAt: longAgo,
    })
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: `Bearer ${rawKey}` },
    })
    expect(res.statusCode).toBe(401)
    expect(res.json()).toMatchObject({ error: { code: 'api_key_expired' } })
  })

  it('treats deprecated=true with deprecatedAt=null as still valid (defensive)', async () => {
    // Edge case: someone sets deprecated=true but forgets to stamp the
    // timestamp. isKeyExpired should treat this as not-expired so we don't
    // accidentally lock a customer out of their own account.
    const { customer } = await createSandboxCustomer()
    const { rawKey } = await createLiveKey(customer.id, 'write', {
      deprecated: true,
      deprecatedAt: null,
    })
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: `Bearer ${rawKey}` },
    })
    expect(res.statusCode).toBe(200)
  })

  // ── Header parsing ─────────────────────────────────────────────────────

  it('rejects requests with no Authorization header', async () => {
    const res = await writeApp.inject({ method: 'POST', url: '/test' })
    expect(res.statusCode).toBe(401)
    expect(res.json()).toMatchObject({ error: { code: 'missing_api_key' } })
  })

  it('rejects requests with a non-Bearer scheme', async () => {
    const res = await writeApp.inject({
      method: 'POST',
      url: '/test',
      headers: { authorization: 'Basic dXNlcjpwYXNz' },
    })
    expect(res.statusCode).toBe(401)
    expect(res.json()).toMatchObject({ error: { code: 'missing_api_key' } })
  })
})
