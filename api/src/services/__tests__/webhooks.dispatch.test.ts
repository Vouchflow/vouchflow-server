// Per-app webhook dispatch: a verification on App A only fires endpoints
// belonging to App A — even if the customer has a sibling App B with
// overlapping URLs and event subscriptions.

import { describe, it, expect, beforeEach } from 'vitest'
import crypto from 'node:crypto'
import { dispatchWebhook } from '../webhooks.js'
import { prisma } from '../../lib/prisma.js'
import { HAS_DB, cleanDb, createSandboxCustomer } from '../../__tests__/helpers/testApp.js'

const d = HAS_DB ? describe : describe.skip

d('dispatchWebhook scoping', () => {
  beforeEach(async () => cleanDb())

  async function makeEndpoint(customerId: string, appId: string, url: string) {
    return prisma.webhookEndpoint.create({
      data: {
        customerId,
        appId,
        url,
        events: ['verification.complete'],
        secretEncrypted: Buffer.from('placeholder'),
      },
    })
  }

  it('per-app dispatch: App A event creates a delivery only for App A endpoints', async () => {
    const { customer, app: appA } = await createSandboxCustomer()
    const appB = await prisma.app.create({
      data: {
        customerId: customer.id,
        name: 'B', slug: 'b',
        sandboxWriteKey: `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`,
        sandboxReadKey:  `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`,
      },
    })
    const epA = await makeEndpoint(customer.id, appA.id, 'https://a.example.com/hook')
    const epB = await makeEndpoint(customer.id, appB.id, 'https://b.example.com/hook')

    await dispatchWebhook(
      { customerId: customer.id, appId: appA.id },
      {
        event: 'verification.complete',
        session_id: 'ses_x',
        verified: true,
        confidence: 'high',
        context: 'login',
        timestamp: new Date().toISOString(),
        api_version: '2026-04-01',
      },
    )

    const deliveries = await prisma.webhookDelivery.findMany({})
    expect(deliveries).toHaveLength(1)
    expect(deliveries[0].endpointId).toBe(epA.id)
    expect(deliveries[0].endpointId).not.toBe(epB.id)
  })

  it('event-type filter still applies (endpoint not subscribed → not delivered)', async () => {
    const { customer, app: appA } = await createSandboxCustomer()
    await prisma.webhookEndpoint.create({
      data: {
        customerId: customer.id,
        appId: appA.id,
        url: 'https://a.example.com/hook',
        events: ['sign.complete'], // not subscribed to verification.complete
        secretEncrypted: Buffer.from('placeholder'),
      },
    })
    await dispatchWebhook(
      { customerId: customer.id, appId: appA.id },
      {
        event: 'verification.complete',
        session_id: 'ses_x',
        verified: true,
        confidence: 'high',
        context: null,
        timestamp: new Date().toISOString(),
        api_version: '2026-04-01',
      },
    )
    const deliveries = await prisma.webhookDelivery.findMany({})
    expect(deliveries).toHaveLength(0)
  })

  it('back-compat: passing customerId-only string fans out customer-wide (legacy callers)', async () => {
    const { customer, app: appA } = await createSandboxCustomer()
    const appB = await prisma.app.create({
      data: {
        customerId: customer.id,
        name: 'B', slug: 'b',
        sandboxWriteKey: `vsk_sandbox_${crypto.randomBytes(20).toString('hex')}`,
        sandboxReadKey:  `vsk_sandbox_read_${crypto.randomBytes(20).toString('hex')}`,
      },
    })
    await makeEndpoint(customer.id, appA.id, 'https://a.example.com/hook')
    await makeEndpoint(customer.id, appB.id, 'https://b.example.com/hook')

    await dispatchWebhook(customer.id, {
      event: 'verification.complete',
      session_id: 'ses_legacy',
      verified: true,
      confidence: 'high',
      context: null,
      timestamp: new Date().toISOString(),
      api_version: '2026-04-01',
    })
    // Both endpoints get a delivery via the back-compat path.
    const deliveries = await prisma.webhookDelivery.findMany({})
    expect(deliveries).toHaveLength(2)
  })
})
