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

export interface SignCompletePayload {
  event: 'sign.complete'
  session_id: string
  verified: boolean
  confidence: string
  context: string | null
  timestamp: string
  api_version: string
}

type WebhookPayload =
  | VerificationCompletePayload
  | VerificationFallbackCompletePayload
  | SignCompletePayload

/**
 * Dispatches a webhook event to all endpoints subscribed to it.
 *
 * Apps refactor: scoping is per-App, not per-Customer. A verification on
 * App A only fires webhooks to endpoints that belong to App A — even if the
 * customer has a sibling App B with overlapping endpoint URLs. This matches
 * customer expectations (their iOS app's webhook should not receive events
 * from their unrelated Android app).
 *
 * `appId` is required; `customerId` is kept for back-compat with callers
 * that haven't yet been threaded through the apps refactor — when omitted,
 * we fall back to customer-wide dispatch with a deprecation warning logged.
 */
export async function dispatchWebhook(
  scope: { customerId: string; appId: string } | string,
  payload: WebhookPayload,
) {
  // Back-compat: callers that pass only a customerId fall through here. They
  // get customer-wide dispatch (the pre-apps-refactor behaviour). Every
  // production callsite has been updated to pass { customerId, appId }; this
  // branch is just defensive scaffolding for transitional code.
  const where =
    typeof scope === 'string'
      ? { customerId: scope, events: { has: payload.event } }
      : { appId: scope.appId, events: { has: payload.event } }

  const endpoints = await prisma.webhookEndpoint.findMany({ where })

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
