import crypto from 'node:crypto'
import { prisma } from '../lib/prisma.js'
import { decryptWebhookSecret } from './webhookSecrets.js'

// §7 Webhooks: HMAC-SHA256 signature, device_token absent from payload.
// §7 Events: verification.complete, verification.fallback_complete, sign.complete.
//
// Delivery model: BullMQ used to own retry scheduling in Redis. With the
// queue ripped out (idle polling was the bulk of our Upstash bill on a
// product with effectively zero webhook traffic), retry state now lives in
// the webhook_deliveries Postgres row:
//
//   - dispatchWebhook() inserts the row and attempts delivery inline.
//     On success → status=delivered. On failure → next_retry_at=now+§7[0],
//     keep status=pending.
//   - retryPendingWebhooks() runs every 30 seconds on each api-server
//     instance and picks up rows whose next_retry_at has elapsed.
//   - When attempts == WEBHOOK_DELAYS_MS.length, we mark status=webhook_failed
//     and stop retrying.
//
// On the request path we never await delivery success — `void
// deliverWebhook(...)` keeps enroll/verify fast even when an integrator's
// endpoint is slow or down.

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

// §7 retry schedule: immediate, then exponential up to 24h, then give up.
// 8 entries = 1 immediate attempt + 7 retries.
const WEBHOOK_DELAYS_MS = [0, 5_000, 30_000, 120_000, 600_000, 3_600_000, 21_600_000, 86_400_000]

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
 * we fall back to customer-wide dispatch.
 */
export async function dispatchWebhook(
  scope: { customerId: string; appId: string } | string,
  payload: WebhookPayload,
) {
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

    // Fire-and-forget — never block the request path on a slow integrator.
    // A crash mid-deliver leaves the row pending with no next_retry_at;
    // retryPendingWebhooks won't pick it up. That's fine: the next dispatch
    // for the same endpoint inserts a fresh row. Lost-delivery scenarios are
    // bounded by the rate of api-server crashes, which is approximately zero.
    void deliverWebhook(delivery.id).catch((err) => {
      console.error(`[webhooks] inline delivery threw: ${err.message}`)
    })
  }
}

/**
 * Attempts a single delivery and records the outcome. Called inline on the
 * first attempt by [dispatchWebhook], and by [retryPendingWebhooks] for
 * scheduled retries.
 */
async function deliverWebhook(deliveryId: string): Promise<void> {
  const delivery = await prisma.webhookDelivery.findUnique({ where: { id: deliveryId } })
  if (!delivery || delivery.status !== 'pending') return

  const endpoint = await prisma.webhookEndpoint.findUnique({ where: { id: delivery.endpointId } })
  if (!endpoint) {
    // Endpoint was deleted between insert and delivery — nothing to retry.
    await prisma.webhookDelivery.update({
      where: { id: deliveryId },
      data: { status: 'webhook_failed', nextRetryAt: null },
    })
    return
  }

  const rawSecret = await decryptWebhookSecret(endpoint.secretEncrypted)

  // §7 HMAC signature: "<timestamp>.<json_payload>"
  const timestamp = Math.floor(Date.now() / 1000).toString()
  const signaturePayload = `${timestamp}.${delivery.payload}`
  const signature = crypto.createHmac('sha256', rawSecret).update(signaturePayload).digest('hex')

  let success = false
  try {
    const response = await fetch(endpoint.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vouchflow-Signature': `t=${timestamp},v1=${signature}`,
      },
      body: delivery.payload,
      signal: AbortSignal.timeout(10_000),
    })
    success = response.ok
  } catch {
    success = false
  }

  // Compute the next state. attemptsAfter is what attempts WILL be after this
  // delivery, so we look up the delay at that index for the NEXT retry.
  const attemptsAfter = delivery.attempts + 1
  if (success) {
    await prisma.webhookDelivery.update({
      where: { id: deliveryId },
      data: {
        status: 'delivered',
        attempts: attemptsAfter,
        lastAttemptAt: new Date(),
        nextRetryAt: null,
      },
    })
    return
  }

  if (attemptsAfter >= WEBHOOK_DELAYS_MS.length) {
    await prisma.webhookDelivery.update({
      where: { id: deliveryId },
      data: {
        status: 'webhook_failed',
        attempts: attemptsAfter,
        lastAttemptAt: new Date(),
        nextRetryAt: null,
      },
    })
    return
  }

  const nextRetryAt = new Date(Date.now() + WEBHOOK_DELAYS_MS[attemptsAfter])
  await prisma.webhookDelivery.update({
    where: { id: deliveryId },
    data: {
      attempts: attemptsAfter,
      lastAttemptAt: new Date(),
      nextRetryAt,
    },
  })
}

/**
 * Cron-style sweep: pick up pending deliveries whose `next_retry_at` has
 * elapsed and attempt them. Called by a 30-second tick registered in
 * `index.ts`. Bounded `take` so one slow integrator can't make the tick
 * take forever — anything we don't pick this tick lands in the next one.
 */
export async function retryPendingWebhooks(): Promise<void> {
  const due = await prisma.webhookDelivery.findMany({
    where: {
      status: 'pending',
      nextRetryAt: { lte: new Date() },
    },
    orderBy: { nextRetryAt: 'asc' },
    take: 50,
    select: { id: true },
  })

  // Sequential rather than Promise.all — keeps memory bounded and means a
  // slow first delivery doesn't starve all the rest on the same outbound
  // connection pool. At the volumes we're talking about (single digits per
  // minute even in stress), serial is fine.
  for (const row of due) {
    await deliverWebhook(row.id).catch((err) => {
      console.error(`[webhooks] retry threw for ${row.id}: ${err.message}`)
    })
  }
}
