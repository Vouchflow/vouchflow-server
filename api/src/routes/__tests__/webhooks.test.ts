import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { FastifyInstance } from 'fastify'
import webhookRoute from '../webhooks.js'
import { dispatchWebhook, type VerificationCompletePayload } from '../../services/webhooks.js'
import { decryptWebhookSecret } from '../../services/webhookSecrets.js'
import { prisma } from '../../lib/prisma.js'
import {
  HAS_DB,
  buildTestApp,
  cleanDb,
  createSandboxCustomer,
} from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

// Webhook CRUD endpoints (POST /v1/webhooks, GET /v1/customers/:id/webhooks,
// PATCH /v1/webhooks/:id, DELETE /v1/webhooks/:id) — the dashboard's
// webhook UI has been wired to these for ages but they were never
// implemented server-side, so all requests 404'd and the web layer's catch
// fell back to {webhooks: []}.

d('POST /v1/webhooks', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(webhookRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('creates an endpoint and returns the raw secret ONCE', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method:  'POST',
      url:     '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://example.com/hook', events: ['verification.complete'] },
    })
    expect(res.statusCode).toBe(201)
    const body = res.json() as { id: string; url: string; events: string[]; secret: string }
    expect(body.id).toMatch(/^.+/)
    expect(body.url).toBe('https://example.com/hook')
    expect(body.events).toEqual(['verification.complete'])
    expect(body.secret).toMatch(/^whsec_[0-9a-f]{48}$/)

    // The encrypted secret on the row decrypts back to the raw value we
    // returned — the encryption round-trip works end to end.
    const stored = await prisma.webhookEndpoint.findFirst({ where: { customerId: customer.id } })
    const rawAgain = await decryptWebhookSecret(stored!.secretEncrypted)
    expect(rawAgain).toBe(body.secret)
  })

  it('rejects http:// URLs (not localhost)', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method:  'POST',
      url:     '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'http://example.com/hook', events: ['verification.complete'] },
    })
    expect(res.statusCode).toBe(400)
  })

  it('allows http://localhost (sandbox / non-prod)', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method:  'POST',
      url:     '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'http://localhost:3000/hook', events: ['verification.complete'] },
    })
    expect(res.statusCode).toBe(201)
  })

  it('rejects unknown event names', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method:  'POST',
      url:     '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://example.com/h', events: ['device.theft' /* not a real event */] },
    })
    expect(res.statusCode).toBe(400)
  })

  it('rejects empty events array', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const res = await app.inject({
      method:  'POST',
      url:     '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://example.com/h', events: [] },
    })
    expect(res.statusCode).toBe(400)
  })

  it('caps at 5 endpoints per customer (409 endpoint_limit_reached)', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    for (let i = 0; i < 5; i++) {
      const r = await app.inject({
        method:  'POST',
        url:     '/v1/webhooks',
        headers: { authorization: `Bearer ${sandboxWriteKey}` },
        payload: { url: `https://example.com/h${i}`, events: ['verification.complete'] },
      })
      expect(r.statusCode).toBe(201)
    }
    const overLimit = await app.inject({
      method:  'POST',
      url:     '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://example.com/h6', events: ['verification.complete'] },
    })
    expect(overLimit.statusCode).toBe(409)
    expect((overLimit.json() as { error: { code: string } }).error.code).toBe('endpoint_limit_reached')
  })

  it('rejects requests without an API key', async () => {
    const res = await app.inject({
      method:  'POST',
      url:     '/v1/webhooks',
      payload: { url: 'https://example.com/h', events: ['verification.complete'] },
    })
    expect(res.statusCode).toBe(401)
  })
})

d('GET /v1/customers/:id/webhooks', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(webhookRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('returns the customer\'s endpoints with no secrets in the body', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    await app.inject({
      method:  'POST', url: '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://a.example/h', events: ['verification.complete'] },
    })
    await app.inject({
      method:  'POST', url: '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://b.example/h', events: ['verification.fallback_complete'] },
    })

    const res = await app.inject({
      method:  'GET',
      url:     `/v1/customers/${customer.id}/webhooks`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    const body = res.json() as { webhooks: Array<{ id: string; url: string; events: string[]; secret?: string }> }
    expect(body.webhooks).toHaveLength(2)
    expect(body.webhooks.every(w => !('secret' in w))).toBe(true)
    expect(body.webhooks.map(w => w.url).sort()).toEqual(['https://a.example/h', 'https://b.example/h'])
  })

  it('cross-tenant returns empty (uses request.customerId, ignores :id)', async () => {
    const a = await createSandboxCustomer()
    const b = await createSandboxCustomer()
    await app.inject({
      method:  'POST', url: '/v1/webhooks',
      headers: { authorization: `Bearer ${b.sandboxWriteKey}` },
      payload: { url: 'https://b.example/h', events: ['verification.complete'] },
    })

    // a's key on b's URL: must return a's empty list, not b's data.
    const res = await app.inject({
      method:  'GET',
      url:     `/v1/customers/${b.customer.id}/webhooks`,
      headers: { authorization: `Bearer ${a.sandboxWriteKey}` },
    })
    expect((res.json() as { webhooks: unknown[] }).webhooks).toHaveLength(0)
  })
})

d('PATCH /v1/webhooks/:id', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(webhookRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('updates events array', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const created = await app.inject({
      method:  'POST', url: '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://example.com/h', events: ['verification.complete'] },
    })
    const id = (created.json() as { id: string }).id

    const patched = await app.inject({
      method:  'PATCH', url: `/v1/webhooks/${id}`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { events: ['verification.complete', 'verification.fallback_complete'] },
    })
    expect(patched.statusCode).toBe(200)
    expect((patched.json() as { events: string[] }).events).toEqual([
      'verification.complete', 'verification.fallback_complete',
    ])
  })

  it('returns 404 for an endpoint owned by another customer (no info leak)', async () => {
    const a = await createSandboxCustomer()
    const b = await createSandboxCustomer()
    const created = await app.inject({
      method:  'POST', url: '/v1/webhooks',
      headers: { authorization: `Bearer ${b.sandboxWriteKey}` },
      payload: { url: 'https://b.example/h', events: ['verification.complete'] },
    })
    const id = (created.json() as { id: string }).id

    const res = await app.inject({
      method:  'PATCH', url: `/v1/webhooks/${id}`,
      headers: { authorization: `Bearer ${a.sandboxWriteKey}` },
      payload: { events: ['verification.complete'] },
    })
    expect(res.statusCode).toBe(404)
  })

  it('rejects an empty body (must include url or events)', async () => {
    const { sandboxWriteKey } = await createSandboxCustomer()
    const created = await app.inject({
      method:  'POST', url: '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://example.com/h', events: ['verification.complete'] },
    })
    const id = (created.json() as { id: string }).id

    const res = await app.inject({
      method:  'PATCH', url: `/v1/webhooks/${id}`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: {},
    })
    expect(res.statusCode).toBe(400)
  })
})

d('DELETE /v1/webhooks/:id', () => {
  let app: FastifyInstance

  beforeAll(async () => {
    app = await buildTestApp(async (fastify) => {
      await fastify.register(webhookRoute, { prefix: '/v1' })
    })
  })

  afterAll(async () => app.close())
  beforeEach(async () => cleanDb())

  it('deletes the endpoint and its delivery history', async () => {
    const { customer, sandboxWriteKey } = await createSandboxCustomer()
    const created = await app.inject({
      method:  'POST', url: '/v1/webhooks',
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
      payload: { url: 'https://example.com/h', events: ['verification.complete'] },
    })
    const id = (created.json() as { id: string }).id

    await prisma.webhookDelivery.create({
      data: { endpointId: id, event: 'verification.complete', payload: '{}', status: 'pending' },
    })

    const res = await app.inject({
      method:  'DELETE', url: `/v1/webhooks/${id}`,
      headers: { authorization: `Bearer ${sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(204)

    expect(await prisma.webhookEndpoint.count({ where: { customerId: customer.id } })).toBe(0)
    expect(await prisma.webhookDelivery.count({ where: { endpointId: id } })).toBe(0)
  })

  it('returns 404 for someone else\'s endpoint', async () => {
    const a = await createSandboxCustomer()
    const b = await createSandboxCustomer()
    const created = await app.inject({
      method:  'POST', url: '/v1/webhooks',
      headers: { authorization: `Bearer ${b.sandboxWriteKey}` },
      payload: { url: 'https://b.example/h', events: ['verification.complete'] },
    })
    const id = (created.json() as { id: string }).id

    const res = await app.inject({
      method:  'DELETE', url: `/v1/webhooks/${id}`,
      headers: { authorization: `Bearer ${a.sandboxWriteKey}` },
    })
    expect(res.statusCode).toBe(404)
  })
})

// ─── dispatchWebhook fan-out filter ─────────────────────────────────────────

d('dispatchWebhook events filter', () => {
  beforeEach(async () => cleanDb())

  function makePayload(): VerificationCompletePayload {
    return {
      event:       'verification.complete',
      session_id:  'ses_abc',
      verified:    true,
      confidence:  'high',
      context:     'login',
      timestamp:   new Date().toISOString(),
      api_version: '2026-04-01',
    }
  }

  it('only enqueues deliveries for endpoints subscribed to the event', async () => {
    const { customer } = await createSandboxCustomer()

    // Endpoint A: subscribed to BOTH events → should receive
    const a = await prisma.webhookEndpoint.create({
      data: {
        customerId:      customer.id,
        url:             'https://a.example/h',
        events:          ['verification.complete', 'verification.fallback_complete'],
        secretEncrypted: Buffer.from(''),
      },
    })
    // Endpoint B: only fallback_complete → should NOT receive verification.complete
    const b = await prisma.webhookEndpoint.create({
      data: {
        customerId:      customer.id,
        url:             'https://b.example/h',
        events:          ['verification.fallback_complete'],
        secretEncrypted: Buffer.from(''),
      },
    })
    // Endpoint C: empty events array → should never receive anything
    const c = await prisma.webhookEndpoint.create({
      data: {
        customerId:      customer.id,
        url:             'https://c.example/h',
        events:          [],
        secretEncrypted: Buffer.from(''),
      },
    })

    await dispatchWebhook(customer.id, makePayload())

    const deliveries = await prisma.webhookDelivery.findMany({})
    const endpointIds = deliveries.map(d => d.endpointId).sort()
    expect(endpointIds).toEqual([a.id])
    // Negative assertions: nothing for b or c
    expect(endpointIds).not.toContain(b.id)
    expect(endpointIds).not.toContain(c.id)
  })

  it('does not deliver across customers', async () => {
    const { customer: customerA } = await createSandboxCustomer()
    const { customer: customerB } = await createSandboxCustomer()

    await prisma.webhookEndpoint.create({
      data: {
        customerId:      customerB.id,
        url:             'https://b.example/h',
        events:          ['verification.complete'],
        secretEncrypted: Buffer.from(''),
      },
    })

    await dispatchWebhook(customerA.id, makePayload())

    expect(await prisma.webhookDelivery.count()).toBe(0)
  })
})
