import crypto from 'node:crypto'
import { prisma } from '../lib/prisma.js'
import { webhookQueue } from '../lib/queues.js'

// §7 Webhooks: HMAC-SHA256 signature, device_token absent from payload
// §7 Events: verification.complete, verification.fallback_complete

export interface VerificationCompletePayload {
  event: 'verification.complete'
  session_id: string
  verified: boolean
  confidence: string
  context: string | null
  timestamp: string
  api_version: string
}

export interface VerificationFallbackCompletePayload {
  event: 'verification.fallback_complete'
  session_id: string
  verified: boolean
  confidence: 'low'
  fallback_method: string
  fallback_reason: string | null
  context: string | null
  timestamp: string
  api_version: string
}

type WebhookPayload = VerificationCompletePayload | VerificationFallbackCompletePayload

export async function dispatchWebhook(customerId: string, payload: WebhookPayload) {
  const endpoints = await prisma.webhookEndpoint.findMany({
    where: { customerId },
  })

  for (const endpoint of endpoints) {
    const delivery = await prisma.webhookDelivery.create({
      data: {
        endpointId: endpoint.id,
        event: payload.event,
        payload: JSON.stringify(payload),
        status: 'pending',
      },
    })

    // Enqueue for immediate delivery with retry schedule per §7:
    // Immediate → 5s → 30s → 2m → 10m → 1h → 6h → 24h → webhook_failed
    // Pass endpointId so the worker can decrypt the secret at delivery time.
    await webhookQueue.add(
      'deliver',
      { deliveryId: delivery.id, url: endpoint.url, endpointId: endpoint.id },
      { attempts: 8, backoff: { type: 'custom' } },
    )
  }
}
